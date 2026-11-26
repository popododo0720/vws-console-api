package proxmox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// drFile holds the cold-DR settings beside registration.json. It is its own
// file so that registration.json keeps the schema of earlier releases and an
// older daemon, which ignores a file it does not know, still starts.
const drFile = "dr.json"

// drState is one DR record of dr.json: the PVE storage of the PBS, the PBS
// target, the read-only PBS token and the registration.json it belongs to.
type drState struct {
	Storage     string `json:"storage"`
	Repository  string `json:"repository"`
	Namespace   string `json:"namespace"`
	Fingerprint string `json:"fingerprint"`
	TokenID     string `json:"tokenId"`
	Token       string `json:"token"`

	Registration drBinding `json:"registration"`
}

// drBinding names the one registration.json a DR record belongs to: the
// SHA-256 of its bytes and its device, inode and birth time. Every write of
// registration.json, by any daemon, an older one included, makes a new file,
// and the birth time tells it apart from an earlier file with a reused inode
// and the same bytes, so a record never carries over to a registration it
// was not written for. Without a birth time there is no binding and no DR.
type drBinding struct {
	Digest string `json:"digest"`
	File   fileID `json:"file"`
}

// bound reports whether file identifies one file across its lifetime.
func bound(file fileID) bool { return file.Ino != 0 && file.Btime != 0 }

func (b drBinding) matches(digest string, file fileID) bool {
	return bound(file) && b.Digest == digest && b.File == file
}

// drContent is dr.json: the records of at most two registration.json files.
// During a registration it holds the committed one and the next one; the
// rename of registration.json picks which applies, and the next write drops
// the other. Absent, or with no record for the current registration.json,
// means DR is not configured.
type drContent struct {
	Records []drState `json:"records"`
}

func (d drState) settings() resource.DRSettings {
	return resource.DRSettings{
		Storage: d.Storage, Repository: d.Repository, Namespace: d.Namespace,
		Fingerprint: d.Fingerprint, TokenID: d.TokenID,
	}
}

// decodeDR reads dr.json. Every record must have valid settings, a token
// and a known registration identity.
func decodeDR(data []byte) ([]drState, error) {
	var c drContent
	if err := decodeStrict(data, &c); err != nil {
		return nil, err
	}
	if len(c.Records) == 0 || len(c.Records) > 2 {
		return nil, resource.Invalid("records", "expected one or two DR records")
	}
	for _, d := range c.Records {
		if !d.settings().Configured() {
			return nil, resource.Invalid("dr", "no DR settings")
		}
		if err := resource.CheckDRSettings(d.settings()); err != nil {
			return nil, err
		}
		if !registrationSecret.MatchString(d.Token) {
			return nil, resource.Invalid("token", "expected 1-512 token characters")
		}
		if len(d.Registration.Digest) != 64 || !bound(d.Registration.File) {
			return nil, resource.Invalid("registration", "expected the digest and identity of registration.json")
		}
	}
	return c.Records, nil
}

// pbsTarget is the PBS side of cold DR: the repository and namespace that
// hold the region's backups and the read-only token that restores from them.
// Its token is a secret; only the Authorization header carries it.
type pbsTarget struct {
	address, datastore, namespace, fingerprint string
	tokenID, token                             string
}

// target returns the PBS target of d, which decodeDR or CheckDRSettings accepted.
func (d *drState) target() *pbsTarget {
	repo, err := resource.ParsePBSRepository(d.Repository)
	if err != nil {
		return nil
	}
	return &pbsTarget{
		address: repo.Address, datastore: repo.Datastore, namespace: d.Namespace,
		fingerprint: d.Fingerprint, tokenID: d.TokenID, token: d.Token,
	}
}

// pbsReaderPrivilege reports whether the PBS DatastoreReader role holds
// privilege: it lists, reads and verifies backups.
func pbsReaderPrivilege(privilege string) bool {
	return privilege == "Datastore.Audit" || privilege == "Datastore.Read" || privilege == "Datastore.Verify"
}

// client trusts exactly the certificate with the registered fingerprint, as
// proxmox-backup-client does, and never the system roots.
func (p *pbsTarget) client() *http.Client {
	want := p.fingerprint
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSHandshakeTimeout: dialTimeout,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// The fingerprint replaces chain verification; VerifyConnection checks it.
				InsecureSkipVerify: true, //nolint:gosec // pinned by VerifyConnection below
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no PBS certificate")
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
					if pbsFingerprintOf(sum[:]) != want {
						return errors.New("PBS certificate fingerprint differs from pbsFingerprint")
					}
					return nil
				},
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func pbsFingerprintOf(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// permissions reads GET /api2/json/access/permissions for the token, for
// path when it is set: PBS maps each ACL path to the names of the privileges
// the token holds there. Without path it lists the ACL nodes where the token
// holds anything; with path it answers the privileges at that path, inherited
// ones included.
func (p *pbsTarget) permissions(
	ctx context.Context, client *http.Client, path string,
) (_ map[string]map[string]bool, retErr error) {
	target := "https://" + p.address + "/api2/json/access/permissions"
	if path != "" {
		target += "?" + url.Values{"path": {path}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build PBS request: %w", err)
	}
	req.Header.Set("Authorization", "PBSAPIToken="+p.tokenID+":"+p.token)
	resp, err := client.Do(req)
	if err != nil {
		// The URL holds no secret; the error names the address only.
		return nil, fmt.Errorf("call PBS %s: %w", p.address, err)
	}
	defer func() { retErr = errors.Join(retErr, resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read PBS permissions: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PBS permissions: HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Data map[string]map[string]bool `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Data == nil {
		return nil, errors.New("PBS permissions: missing or invalid data")
	}
	return envelope.Data, nil
}

const (
	// pbsMaxListed bounds the ACL nodes a DR token may list.
	pbsMaxListed = 64
	// pbsMaxPath is the longest ACL path PBS accepts.
	pbsMaxPath = 128
)

// pbsProbeName is a fresh child name for an inheritance probe. It is random
// per call, so it is never an ACL node.
func pbsProbeName() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return "vp" + hex.EncodeToString(b)
}

// checkPBS admits a token that can read the DR namespace N and nothing the
// daemon can find outside it. All four rules must hold:
//
//  1. Every ACL node the token lists is N or below it and holds only
//     DatastoreReader privileges, and it lists at most 64.
//  2. Every strict ancestor of N holds nothing.
//  3. A fresh child of every ancestor and of /access, /remote, /system and
//     /tape holds nothing, and a fresh child of N and of every listed node
//     holds only DatastoreReader privileges. This catches a grant that
//     propagates below a node where a non-propagating entry hides it.
//  4. N holds Datastore.Read.
//
// It cannot see a grant below an ACL node that PBS does not list for the
// token, at a path the daemon cannot guess; the token's provisioning
// excludes it (docs/region-daemon.md).
func checkPBS(ctx context.Context, p *pbsTarget) error {
	refuse := func(format string, args ...any) error {
		return &selfCheckError{check: "pbs_privileges", cause: fmt.Errorf("proxmox: PBS token "+format, args...)}
	}
	client := p.client()
	defer client.CloseIdleConnections()
	lookup := func(path string) (map[string]bool, error) {
		if len(path) > pbsMaxPath {
			return nil, refuse("probe path %s exceeds %d characters", path, pbsMaxPath)
		}
		held, err := p.permissions(ctx, client, path)
		if err != nil {
			return nil, &selfCheckError{check: "pbs_connection", cause: fmt.Errorf("proxmox: check PBS token: %w", err)}
		}
		return held[path], nil
	}
	// only looks up path and refuses any privilege there, or with reader set
	// any privilege DatastoreReader does not hold.
	only := func(path string, reader bool) (map[string]bool, error) {
		held, err := lookup(path)
		if err != nil {
			return nil, err
		}
		for privilege := range held {
			if !reader || !pbsReaderPrivilege(privilege) {
				return nil, refuse("holds %s on %s", privilege, path)
			}
		}
		return held, nil
	}

	namespace := "/datastore/" + p.datastore + "/" + p.namespace
	listed, err := p.permissions(ctx, client, "")
	if err != nil {
		return &selfCheckError{check: "pbs_connection", cause: fmt.Errorf("proxmox: check PBS token: %w", err)}
	}
	if len(listed) > pbsMaxListed {
		return refuse("lists %d ACL paths, more than %d", len(listed), pbsMaxListed)
	}
	for path, privileges := range listed {
		for privilege := range privileges {
			if !pbsReaderPrivilege(privilege) || path != namespace && !strings.HasPrefix(path, namespace+"/") {
				return refuse("holds %s on %s", privilege, path)
			}
		}
	}
	ancestors := []string{"/", "/datastore", "/datastore/" + p.datastore}
	parts := strings.Split(p.namespace, "/")
	for i := 1; i < len(parts); i++ {
		ancestors = append(ancestors, "/datastore/"+p.datastore+"/"+strings.Join(parts[:i], "/"))
	}
	for _, path := range ancestors {
		if _, err := only(path, false); err != nil {
			return err
		}
	}
	child := func(path string) string { return strings.TrimSuffix(path, "/") + "/" + pbsProbeName() }
	for _, path := range append(ancestors, "/access", "/remote", "/system", "/tape") {
		if _, err := only(child(path), false); err != nil {
			return err
		}
	}
	for _, path := range append([]string{namespace}, keys(listed)...) {
		if _, err := only(child(path), true); err != nil {
			return err
		}
	}
	held, err := only(namespace, true)
	if err != nil {
		return err
	}
	if _, ok := held["Datastore.Read"]; !ok {
		return refuse("lacks Datastore.Read on %s", namespace)
	}
	return nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// checkDRStorage requires storage to be a PVE storage of type pbs.
func checkDRStorage(ctx context.Context, client *pveclient.Client, storage string) error {
	rows, err := client.ClusterResources(ctx, pveclient.ResourceStorage)
	if err != nil {
		return &selfCheckError{check: "dr_storage", cause: fmt.Errorf("proxmox: check drStorage: %w", err)}
	}
	known := false
	for _, row := range rows {
		if row.Type != "storage" || row.Storage != storage {
			continue
		}
		if row.PluginType == "pbs" {
			return nil
		}
		known = true
	}
	if known {
		return &selfCheckError{check: "dr_storage", cause: fmt.Errorf("proxmox: drStorage %q is not a PBS storage", storage)}
	}
	return &selfCheckError{check: "dr_storage", cause: fmt.Errorf("proxmox: drStorage: unknown storage %q", storage)}
}
