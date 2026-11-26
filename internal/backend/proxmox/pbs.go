package proxmox

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// pbsTarget is the PBS side of cold DR: the repository and namespace that
// hold the region's backups and the read-only token that restores from them.
// Its token is a secret; only the Authorization header carries it.
type pbsTarget struct {
	address, datastore, namespace, fingerprint string
	tokenID, token                             string
}

// pbsReaderPrivilege reports whether the PBS DatastoreReader role holds privilege.
func pbsReaderPrivilege(privilege string) bool {
	return privilege == "Datastore.Audit" || privilege == "Datastore.Read"
}

// pbsTargetOf returns the PBS target of a registration that decodeRegistration
// accepted, and false for a region without DR.
func pbsTargetOf(s registrationSnapshot) (*pbsTarget, bool) {
	repo, err := resource.ParsePBSRepository(s.PBSRepository)
	if s.PBSTokenID == "" || err != nil {
		return nil, false
	}
	return &pbsTarget{
		address: repo.Address, datastore: repo.Datastore, namespace: s.PBSNamespace,
		fingerprint: s.PBSFingerprint, tokenID: s.PBSTokenID, token: s.PBSToken,
	}, true
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

// permissions reads GET /api2/json/access/permissions for the token: PBS
// lists each ACL path where the token holds a privilege, with the names of
// the privileges it holds there.
func (p *pbsTarget) permissions(ctx context.Context) (_ map[string]map[string]bool, retErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+p.address+"/api2/json/access/permissions", nil)
	if err != nil {
		return nil, fmt.Errorf("build PBS request: %w", err)
	}
	req.Header.Set("Authorization", "PBSAPIToken="+p.tokenID+":"+p.token)
	client := p.client()
	defer client.CloseIdleConnections()
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

// checkPBS admits a token that can read the DR namespace and do nothing
// else: every privilege it holds is one of DatastoreReader's, on the
// namespace or below it, and it holds Datastore.Read on the namespace.
func checkPBS(ctx context.Context, p *pbsTarget, cfg RegionConfig) error {
	if cfg.DRStorage == "" {
		return &selfCheckError{check: "dr_storage", cause: errors.New("proxmox: a PBS registration needs dr_storage")}
	}
	held, err := p.permissions(ctx)
	if err != nil {
		return &selfCheckError{check: "pbs_connection", cause: fmt.Errorf("proxmox: check PBS token: %w", err)}
	}
	namespace := "/datastore/" + p.datastore + "/" + p.namespace
	for path, privileges := range held {
		for privilege := range privileges {
			if !pbsReaderPrivilege(privilege) || path != namespace && !strings.HasPrefix(path, namespace+"/") {
				return &selfCheckError{
					check: "pbs_privileges", cause: fmt.Errorf("proxmox: PBS token holds %s on %s", privilege, path),
				}
			}
		}
	}
	if _, ok := held[namespace]["Datastore.Read"]; !ok {
		return &selfCheckError{
			check: "pbs_privileges", cause: fmt.Errorf("proxmox: PBS token lacks Datastore.Read on %s", namespace),
		}
	}
	return nil
}
