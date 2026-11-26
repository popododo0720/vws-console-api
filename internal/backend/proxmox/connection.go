package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ErrUnregistered is the readiness state of a daemon with no registration.
var ErrUnregistered = errors.New("unregistered")

// errNoEndpoints is the state of a registration file written before it carried
// pveApiUrls and caPem.
var errNoEndpoints = errors.New("registration has no valid pveApiUrls and caPem; register the region again")

// maxRegistrationBytes bounds the registration request and the state file.
const (
	maxRegistrationBytes = 65 << 10
	registrationFile     = "registration.json"
	fenceFile            = "generation.json"
	// dialTimeout bounds the connect and the TLS handshake to one address.
	dialTimeout = time.Second
)

var (
	registrationRegion  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	registrationCluster = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$`)
	registrationTokenID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`)
	registrationSecret  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,512}$`)
)

// registrationSnapshot is both the registration request and the state file
// content. Tokens are plain strings because the state file stores them.
type registrationSnapshot struct {
	Region string `json:"region"`
	//nolint:tagliatelle // The registration protocol names cluster_name.
	ClusterName string `json:"cluster_name"`
	// PVEAPIURLs are the node addresses of the one cluster, in order; CAPEM
	// is the only trust root for all of them.
	PVEAPIURLs []string       `json:"pveApiUrls"`
	CAPEM      string         `json:"caPem"`
	Zones      []backend.Zone `json:"zones"`
	TokenID    string         `json:"tokenId"`
	Token      string         `json:"token,omitempty"`
	// Generation is the registry version of this registration. A daemon
	// refuses one older than the highest it has accepted; 0 means unfenced.
	Generation int64 `json:"generation,omitempty"`

	FirewallTokenID string `json:"firewallTokenId,omitempty"`
	FirewallToken   string `json:"firewallToken,omitempty"`

	BackupTokenID string `json:"backupTokenId,omitempty"`
	BackupToken   string `json:"backupToken,omitempty"`
}

// registrationRequest is a registration push: the content of
// registration.json and the cold-DR settings, which go to dr.json. The DR
// settings are all set, or all empty for a region without DR; PBSToken is a
// read-only PBS API token.
type registrationRequest struct {
	registrationSnapshot

	DRStorage      string `json:"drStorage,omitempty"`
	PBSRepository  string `json:"pbsRepository,omitempty"`
	PBSNamespace   string `json:"pbsNamespace,omitempty"`
	PBSFingerprint string `json:"pbsFingerprint,omitempty"`
	PBSTokenID     string `json:"pbsTokenId,omitempty"`
	PBSToken       string `json:"pbsToken,omitempty"`
}

func (r registrationRequest) dr() resource.DRSettings {
	return resource.DRSettings{
		Storage: r.DRStorage, Repository: r.PBSRepository, Namespace: r.PBSNamespace,
		Fingerprint: r.PBSFingerprint, TokenID: r.PBSTokenID,
	}
}

// Connection serves the one region this instance is named for. Its state is
// 0600 files under the state directory: registration.json with the PVE
// tokens, generation.json and, with cold DR, dr.json with the PBS token.
type Connection struct {
	mu          sync.Mutex
	config      RegionConfig
	region, dir string
	client      *http.Client // pinned to clientCA
	base        *http.Transport
	endpoints   *pveclient.Endpoints // shared by every check of one address list and CA
	endpointsID string
	clientCA    string
	current     *Backend
	digest      [32]byte
	// dialPVE replaces the network dialer of connection tests; tests use it
	// to make PVE reachable from this process alone.
	dialPVE func(ctx context.Context, network, addr string) (net.Conn, error)
	// step, when set, is called before each stage of a removal and before
	// Register persists the state file, and fails it by returning an error;
	// tests use it.
	step func(stage string) error
}

// Open loads node-local configuration; registration may arrive after startup.
// The state directory is created 0700 (or must already be private) and leftover temporary files are removed.
// PVE addresses and the CA come from the registration only.
func Open(configPath, region, stateDir string) (*Connection, error) {
	if !registrationRegion.MatchString(region) {
		return nil, errors.New("proxmox: -region must be a lowercase DNS label")
	}
	cfg, err := LoadRegion(configPath)
	if err != nil {
		return nil, err
	}
	stateDir, err = ensurePrivateDir(stateDir, syncDir)
	if err != nil {
		return nil, fmt.Errorf("proxmox: state dir: %w", err)
	}
	for _, name := range []string{registrationFile, fenceFile, drFile} {
		if err := removeStaleTemps(stateDir, name); err != nil {
			return nil, err
		}
	}
	return &Connection{config: cfg, region: region, dir: stateDir}, nil
}

// Close drops idle PVE connections.
func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

// httpClient trusts the registered CA and nothing else, never the system roots.
func (c *Connection) httpClient(caPEM string) (*http.Client, error) {
	if c.client != nil && c.clientCA == caPEM {
		return c.client, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, resource.Invalid("caPem", "expected PEM certificates")
	}
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
	c.base = &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		// A dead address must not use up the call's budget before the next is tried.
		DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout: dialTimeout,
	}
	c.client, c.clientCA = &http.Client{
		Transport:     c.base,
		Timeout:       10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, caPEM
	return c.client, nil
}

// endpointsFor returns the failover transport of s. Repeated checks of the
// same list and CA share one, so the current address survives a reload and
// a dead first address costs one failed dial, not one per check.
func (c *Connection) endpointsFor(s registrationSnapshot) (*pveclient.Endpoints, error) {
	key := s.CAPEM + "\n" + strings.Join(s.PVEAPIURLs, "\n")
	if c.endpoints != nil && c.endpointsID == key && c.endpoints.Transport() == c.base {
		return c.endpoints, nil
	}
	endpoints, err := pveclient.NewEndpoints(c.base, s.PVEAPIURLs, errNoQuorum())
	if err != nil {
		return nil, fmt.Errorf("proxmox: endpoints: %w", err)
	}
	c.endpoints, c.endpointsID = endpoints, key
	return endpoints, nil
}

// encodeState is the content of registration.json. The generation lives only
// in generation.json, so the file keeps the schema of earlier releases and a
// daemon rolled back to one still reads it.
func encodeState(s registrationSnapshot) ([]byte, error) {
	s.Generation = 0
	state, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode registration: %w", err)
	}
	return state, nil
}

// decodeStrict decodes the one JSON document of data into v and refuses
// unknown fields.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return resource.Invalid("registration", "invalid JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return resource.Invalid("registration", "expected one JSON document")
	}
	return nil
}

// decodeRegistration reads a registration push.
func decodeRegistration(data []byte) (registrationRequest, error) {
	var r registrationRequest
	if err := decodeStrict(data, &r); err != nil {
		return r, err
	}
	if err := resource.CheckDRSettings(r.dr()); err != nil {
		return r, err
	}
	if r.PBSTokenID == "" && r.PBSToken != "" {
		return r, resource.Invalid("pbsTokenId", "expected user@realm!token")
	}
	var err error
	r.registrationSnapshot, err = checkSnapshot(r.registrationSnapshot)
	return r, err
}

// decodeState reads registration.json, which has no DR settings.
func decodeState(data []byte) (registrationSnapshot, error) {
	var s registrationSnapshot
	if err := decodeStrict(data, &s); err != nil {
		return s, err
	}
	return checkSnapshot(s)
}

func checkSnapshot(s registrationSnapshot) (registrationSnapshot, error) {
	if !registrationRegion.MatchString(s.Region) || !registrationCluster.MatchString(s.ClusterName) ||
		!registrationTokenID.MatchString(s.TokenID) || len(s.Zones) > 26 || s.Generation < 0 {
		return s, resource.Invalid("registration", "invalid region, cluster_name, tokenId or zones")
	}
	if err := resource.CheckPVEAPIURLs(s.PVEAPIURLs); err != nil {
		return s, err
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(s.CAPEM)) {
		return s, resource.Invalid("caPem", "expected the PEM certificates that sign the PVE nodes")
	}
	if s.FirewallTokenID == "" && s.FirewallToken != "" ||
		s.FirewallTokenID != "" && (!registrationTokenID.MatchString(s.FirewallTokenID) || s.FirewallTokenID == s.TokenID) {
		return s, resource.Invalid("firewallTokenId", "expected a second user@realm!token")
	}
	if s.BackupTokenID == "" && s.BackupToken != "" ||
		s.BackupTokenID != "" && (!registrationTokenID.MatchString(s.BackupTokenID) ||
			s.BackupTokenID == s.TokenID || s.BackupTokenID == s.FirewallTokenID) {
		return s, resource.Invalid("backupTokenId", "expected a separate user@realm!token")
	}
	letters, nodes := map[string]bool{}, map[string]bool{}
	for _, z := range s.Zones {
		if len(z.Letter) != 1 || z.Letter < "a" || z.Letter > "z" || letters[z.Letter] || len(z.Nodes) > 256 {
			return s, resource.Invalid("zones", "invalid or repeated letter")
		}
		letters[z.Letter] = true
		for _, node := range z.Nodes {
			if !registrationCluster.MatchString(node) || nodes[node] {
				return s, resource.Invalid("zones", "invalid or repeated node")
			}
			nodes[node] = true
		}
	}
	return s, nil
}

func (c *Connection) check(ctx context.Context, s registrationSnapshot) (*Backend, error) {
	if !registrationSecret.MatchString(string(s.Token)) {
		return nil, resource.Invalid("token", "expected 1-512 token characters")
	}
	if s.FirewallTokenID != "" && !registrationSecret.MatchString(string(s.FirewallToken)) {
		return nil, resource.Invalid("firewallToken", "expected 1-512 token characters")
	}
	if s.BackupTokenID != "" && !registrationSecret.MatchString(string(s.BackupToken)) {
		return nil, resource.Invalid("backupToken", "expected 1-512 token characters")
	}
	pinned, err := c.httpClient(s.CAPEM)
	if err != nil {
		return nil, err
	}
	// One ordered list and one current index serve all three tokens' clients.
	endpoints, err := c.endpointsFor(s)
	if err != nil {
		return nil, errors.New("invalid PVE connection")
	}
	transport := &http.Client{Transport: endpoints, Timeout: pinned.Timeout, CheckRedirect: pinned.CheckRedirect}
	endpoint := s.PVEAPIURLs[0] // only the path root; the transport picks the address
	client, err := pveclient.New(pveclient.Config{
		BaseURL: endpoint, TokenID: s.TokenID, Secret: pveclient.Secret(s.Token), HTTPClient: transport,
	})
	if err != nil {
		return nil, errors.New("invalid PVE connection")
	}
	var firewall *pveclient.Client
	if s.FirewallTokenID != "" {
		firewall, err = pveclient.New(pveclient.Config{
			BaseURL: endpoint, TokenID: s.FirewallTokenID, Secret: pveclient.Secret(s.FirewallToken), HTTPClient: transport,
		})
		if err != nil {
			return nil, errors.New("invalid PVE connection")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := New(ctx, client, Registration{
		Region: backend.ProxmoxRegion{Name: s.Region, Zones: s.Zones}, ClusterName: s.ClusterName,
	}, c.config)
	if err == nil {
		b.endpoints = endpoints
	}
	if err == nil && firewall != nil {
		if err = checkFirewall(ctx, firewall, c.config); err == nil {
			b.firewall = firewall
		}
	}
	if err == nil && s.BackupTokenID != "" {
		var backup *pveclient.Client
		backup, err = pveclient.New(pveclient.Config{
			BaseURL: endpoint, TokenID: s.BackupTokenID, Secret: pveclient.Secret(s.BackupToken), HTTPClient: transport,
		})
		if err == nil {
			if err = checkBackup(ctx, backup, c.config); err == nil {
				b.backup = backup
			}
		}
	}
	if err != nil && resource.AsError(err).Code != resource.CodeConflict {
		return nil, selfCheckFailure(err)
	}
	return b, err
}

// selfCheckFailure is the error a failed self-check answers with: the name
// of the check, never its cause, which may quote PVE or PBS replies.
func selfCheckFailure(err error) error {
	if message := resource.RegistrationFailureMessage(err); message != "" {
		return &resource.Error{Code: resource.CodeUnavailable, Message: message}
	}
	message := "registration self-check failed"
	var failure *selfCheckError
	if errors.As(err, &failure) {
		message += ": " + failure.check
	}
	return &resource.Error{Code: resource.CodeUnavailable, Message: message}
}

// Register validates against PVE, then replaces the state file. The
// in-process mutex serializes registrations and reads; one daemon owns the file.
func (c *Connection) Register(ctx context.Context, data json.RawMessage) error {
	_, err := c.RegisterBackend(ctx, data)
	return err
}

// RegisterBackend is Register that also returns the backend to serve: the one
// its self-check built when the state file changed, else the current one. It
// is the current backend, so the next Check of the same state file returns it
// and the caller can serve it without a second self-check.
func (c *Connection) RegisterBackend(ctx context.Context, data json.RawMessage) (*Backend, error) {
	r, err := decodeRegistration(data)
	if err != nil {
		return nil, err
	}
	s := r.registrationSnapshot
	if s.Region != c.region {
		return nil, resource.Invalid("region", "registration is for another region than this instance")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A pending removal is finished first, whichever path follows: replacing
	// its tombstone with this generation must not leave the removed file.
	f, err := c.finishPendingRemoval()
	if err != nil {
		return nil, err
	}
	if s.Generation < f.Generation || s.Generation == f.Generation && f.Deregistered {
		return nil, errStaleGeneration()
	}
	if s.Token == "" || s.FirewallTokenID != "" && s.FirewallToken == "" ||
		s.BackupTokenID != "" && s.BackupToken == "" {
		stored, _, err := c.registration()
		if err != nil && !errors.Is(err, ErrUnregistered) && !errors.Is(err, errNoEndpoints) {
			return nil, err
		}
		// A stored secret goes only to the destination that already held it.
		unchanged := sameTrust(stored, s)
		if s.Token == "" {
			if stored.TokenID != s.TokenID || stored.Token == "" {
				return nil, resource.Invalid("token", "required for first registration")
			}
			if !unchanged {
				return nil, resource.Invalid("token", "required when caPem or pveApiUrls change")
			}
			s.Token = stored.Token
		}
		if s.FirewallTokenID != "" && s.FirewallToken == "" {
			if !unchanged {
				return nil, resource.Invalid("firewallToken", "required when caPem or pveApiUrls change")
			}
			if stored.FirewallTokenID != s.FirewallTokenID || stored.FirewallToken == "" {
				return nil, resource.Invalid("firewallToken", "required for a new firewall token")
			}
			s.FirewallToken = stored.FirewallToken
		}
		if s.BackupTokenID != "" && s.BackupToken == "" {
			if !unchanged {
				return nil, resource.Invalid("backupToken", "required when caPem or pveApiUrls change")
			}
			if stored.BackupTokenID != s.BackupTokenID || stored.BackupToken == "" {
				return nil, resource.Invalid("backupToken", "required for a new backup token")
			}
			s.BackupToken = stored.BackupToken
		}
	}
	dr, err := c.registeredDR(ctx, r)
	if err != nil {
		return nil, err
	}
	b, err := c.check(ctx, s)
	if err != nil {
		return nil, err
	}
	if dr != nil {
		b.pbs = dr.target()
		if err := checkDRStorage(ctx, b.client, dr.Storage); err != nil {
			return nil, selfCheckFailure(err)
		}
		if err := checkPBS(ctx, dr.target()); err != nil {
			return nil, selfCheckFailure(err)
		}
	}
	if err := c.verifyOtherEndpoints(ctx, s); err != nil {
		return nil, err
	}
	state, err := encodeState(s)
	if err != nil {
		return nil, err
	}
	var drData []byte
	if dr != nil {
		if drData, err = json.Marshal(dr); err != nil {
			return nil, fmt.Errorf("encode DR settings: %w", err)
		}
	}
	if len(state) > maxRegistrationBytes {
		return nil, resource.Invalid("registration", "serialized registration exceeds 65 KiB")
	}
	// The generation is persisted first: a crash between the two files only
	// makes older pushes stale, and the console repeats the registration.
	if want := (fence{Generation: s.Generation}); f != want {
		if err := c.writeFence(want); err != nil {
			return nil, err
		}
	}
	if err := c.at("persist"); err != nil {
		return nil, err
	}
	// dr.json goes first and registration.json is the commit point. Each file
	// is valid without the other, so a crash between them leaves a pair the
	// repeated push converges.
	if err := c.persistDR(drData); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(c.dir, registrationFile, state, nil); err != nil {
		return nil, fmt.Errorf("persist registration: %w", err)
	}
	// The state files hold no generation, so an unchanged registration at a new
	// generation keeps the serving backend, its quorum gate and its consoles.
	if digest := stateDigest(state, drData); c.current == nil || c.digest != digest {
		c.current, c.digest = b, digest
	}
	return c.current, nil
}

// registeredDR is the DR state of r, nil without DR settings. An omitted PBS
// token is taken from dr.json only for the same token id, repository and
// fingerprint, which name where the secret goes; a changed namespace or
// storage keeps it.
func (c *Connection) registeredDR(ctx context.Context, r registrationRequest) (*drState, error) {
	if !r.dr().Configured() {
		return nil, nil //nolint:nilnil // no DR settings is not an error
	}
	dr := &drState{
		Storage: r.DRStorage, Repository: r.PBSRepository, Namespace: r.PBSNamespace,
		Fingerprint: r.PBSFingerprint, TokenID: r.PBSTokenID, Token: r.PBSToken,
	}
	if dr.Token == "" {
		stored, _ := c.storedDR(ctx)
		if stored == nil || stored.TokenID != dr.TokenID || stored.Repository != dr.Repository ||
			stored.Fingerprint != dr.Fingerprint {
			return nil, resource.Invalid("pbsToken", "required for a new PBS token, pbsRepository or pbsFingerprint")
		}
		dr.Token = stored.Token
	}
	if !registrationSecret.MatchString(dr.Token) {
		return nil, resource.Invalid("pbsToken", "expected 1-512 token characters")
	}
	return dr, nil
}

// storedDR reads dr.json: nil and no data when it is absent. An unreadable
// or invalid file is also nil, with an error log: DR is then not configured,
// and the region keeps serving, as when PBS is down.
func (c *Connection) storedDR(ctx context.Context) (*drState, []byte) {
	data, err := readStateFile(c.dir, drFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var dr *drState
	if err == nil {
		dr, err = decodeDR(data)
	}
	if err != nil {
		// The reason is a fixed text or names a field, never the token.
		reason := "unreadable"
		var invalid *resource.Error
		if errors.As(err, &invalid) {
			reason = invalid.Field + ": " + invalid.Message
		}
		slog.ErrorContext(ctx, "proxmox: dr.json is unreadable or invalid; cold DR is not configured",
			slog.String("region", c.region), slog.String("reason", reason))
		return nil, nil
	}
	return dr, data
}

// persistDR writes dr.json, or removes it when data is empty.
func (c *Connection) persistDR(data []byte) error {
	if len(data) > 0 {
		if err := writeFileAtomic(c.dir, drFile, data, nil); err != nil {
			return fmt.Errorf("persist DR settings: %w", err)
		}
		return nil
	}
	if err := os.Remove(filepath.Join(c.dir, drFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove DR settings: %w", err)
	}
	return syncDir(c.dir)
}

// stateDigest identifies the content of both state files.
func stateDigest(state, dr []byte) [32]byte {
	h := sha256.New()
	h.Write(state)
	h.Write([]byte{0})
	h.Write(dr)
	return [32]byte(h.Sum(nil))
}

// fence is the highest registry generation this daemon has accepted, kept in
// its own file so that it outlives the registration. After a removal it is the
// tombstone: Deregistered is true and every registration at or below
// Generation is refused, so a push delayed in the network or sent by another
// console replica cannot bring the region back. A tombstone is Pending from
// its write until the unlink of registration.json is synced. RemovedDigest
// (hex SHA-256 of the bytes) and RemovedFile (device, inode and birth time) name the
// file that removal unlinks, so a file beside a tombstone can be told apart
// from one a rolled-back daemon wrote since, even with the same bytes.
type fence struct {
	Generation    int64  `json:"generation"`
	Deregistered  bool   `json:"deregistered"`
	Pending       bool   `json:"pending,omitempty"`
	RemovedDigest string `json:"removedDigest,omitempty"`
	RemovedFile   fileID `json:"removedFile,omitzero"`
}

// fileID identifies one file. A write by temporary file and rename always
// makes a new inode with a new birth time, so equal bytes written again do not
// have the same fileID, while chmod and chown keep it. Btime is 0 where the
// platform reports no birth time. The zero value means the identity is
// unknown.
type fileID struct {
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Btime int64  `json:"btimeNs,omitempty"`
}

// sameFile reports whether a and b name the same known file. Birth times are
// compared only when both lookups report one, since statx may report it on one
// lookup and not the next.
func (a fileID) sameFile(b fileID) bool {
	if a.Ino == 0 || a.Dev != b.Dev || a.Ino != b.Ino {
		return false
	}
	return a.Btime == 0 || b.Btime == 0 || a.Btime == b.Btime
}

func errStaleGeneration() error {
	return &resource.Error{Code: resource.CodeConflict, Message: "generation is older than the daemon's current one"}
}

func (c *Connection) readFence() (fence, error) {
	var f fence
	data, err := os.ReadFile(filepath.Join(c.dir, fenceFile))
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil || json.Unmarshal(data, &f) != nil || f.Generation < 0 {
		return f, errors.New("generation file unreadable")
	}
	return f, nil
}

func (c *Connection) writeFence(f fence) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode generation: %w", err)
	}
	if err := writeFileAtomic(c.dir, fenceFile, data, nil); err != nil {
		return fmt.Errorf("persist generation: %w", err)
	}
	return nil
}

// stateFile returns the hex SHA-256 and the identity of registration.json, or
// "" when there is none. The identity is zero when the platform has none.
func (c *Connection) stateFile() (string, fileID, error) {
	file := filepath.Join(c.dir, registrationFile)
	info, err := os.Lstat(file)
	if errors.Is(err, os.ErrNotExist) {
		return "", fileID{}, nil
	}
	var data []byte
	if err == nil {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return "", fileID{}, errors.New("registration unreadable")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), fileIdentity(file, info), nil
}

// finishPendingRemoval settles a tombstone beside registration.json and
// returns the fence that holds afterwards. It runs under the mutex on startup,
// on every reload and before every Register and Deregister, before the stored
// credentials can be read or the tombstone replaced.
//
// A pending tombstone owns the file only when both its RemovedDigest and its
// known RemovedFile match: the unlink is still owed (a crash or a failed
// unlink), and it is finished, synced and the tombstone marked done. From the
// moment a pending tombstone owns the registration it is gone: the error
// always matches ErrUnregistered, joined with the storage error when the
// cleanup failed, and the next call retries the cleanup. Any other file beside
// a tombstone (the tombstone is done, or the bytes, the inode or the birth
// time differ, or the identity is unknown) was written since by a rolled-back daemon, which does
// not know the fence: it is kept and served, and the tombstone becomes a plain
// fence at the same generation, so older generations stay refused.
func (c *Connection) finishPendingRemoval() (fence, error) {
	f, err := c.readFence()
	if err != nil || !f.Deregistered {
		return f, err
	}
	digest, id, err := c.stateFile()
	if err != nil {
		return f, err
	}
	owned := f.Pending && digest == f.RemovedDigest && id.sameFile(f.RemovedFile)
	if digest != "" && !owned {
		f = fence{Generation: f.Generation}
		return f, c.writeFence(f)
	}
	if !f.Pending {
		return f, nil
	}
	if err := c.completeRemoval(f.Generation, digest != ""); err != nil {
		return f, errors.Join(ErrUnregistered, err)
	}
	return fence{Generation: f.Generation, Deregistered: true}, nil
}

// completeRemoval finishes the removal a pending tombstone at generation owns:
// it drops the cached backend, removes dr.json, unlinks registration.json when unlink is set,
// syncs the directory and marks the tombstone done. A failure leaves the
// pending tombstone, so a later call repeats it.
func (c *Connection) completeRemoval(generation int64, unlink bool) error {
	c.dropBackend()
	// dr.json goes before registration.json, so no DR settings outlive it.
	if err := os.Remove(filepath.Join(c.dir, drFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove DR settings: %w", err)
	}
	if unlink {
		if err := c.at("unlink"); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(c.dir, registrationFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove registration: %w", err)
		}
	}
	if err := c.at("sync"); err != nil {
		return err
	}
	if err := syncDir(c.dir); err != nil {
		return err
	}
	return c.writeFence(fence{Generation: generation, Deregistered: true})
}

func (c *Connection) dropBackend() {
	c.current, c.digest = nil, [32]byte{}
	c.endpoints, c.endpointsID = nil, ""
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

// at calls the test hook before stage; an error from it fails the caller there.
func (c *Connection) at(stage string) error {
	if c.step == nil {
		return nil
	}
	return c.step(stage)
}

// Deregister forgets the registration, and with it every token secret, in
// this order under the mutex of Register and Check: stale temporary files go,
// a pending tombstone with the generation and the digest and identity of
// registration.json is persisted, the file is unlinked, the directory is
// fsynced and the tombstone is marked done. The request names the region,
// which must match -region, and a generation, which must be at least the
// highest accepted (equal only to repeat a removal); anything older is refused
// with 409 and changes nothing.
//
// removed reports whether the registration is gone. A failure before the
// pending tombstone is persisted changes no registration and the caller keeps
// serving. Once it is persisted the removal is committed: removed is true even
// when err is non-nil (the unlink, the directory sync or the done marker
// failed), the caller must stop everything that runs on the old registration,
// and a repeat or the next reload finishes the cleanup. It is idempotent: with
// no file it still syncs.
func (c *Connection) Deregister(ctx context.Context, data json.RawMessage) (removed bool, err error) {
	var req struct {
		Region     string `json:"region"`
		Generation int64  `json:"generation"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var extra any
	if !uniqueKeys(data) || dec.Decode(&req) != nil || !errors.Is(dec.Decode(&extra), io.EOF) || req.Generation < 1 {
		return false, resource.Invalid("deregistration", "expected one JSON object with region and generation, each once")
	}
	if req.Region != c.region {
		return false, resource.Invalid("region", "deregistration is for another region than this instance")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A request that gave up while it waited for the lock changes nothing. Once
	// the pending tombstone is written, the removal finishes or is resumed.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := c.at("cleanup"); err != nil {
		return false, err
	}
	for _, name := range []string{registrationFile, fenceFile, drFile} {
		if err := removeStaleTemps(c.dir, name); err != nil {
			return false, err
		}
	}
	f, err := c.finishPendingRemoval()
	if errors.Is(err, ErrUnregistered) {
		return true, err
	}
	if err != nil {
		return false, err
	}
	if req.Generation < f.Generation || req.Generation == f.Generation && !f.Deregistered {
		return false, errStaleGeneration()
	}
	if f.Generation == req.Generation {
		c.dropBackend()
		if err := c.at("sync"); err != nil {
			return true, err
		}
		return true, syncDir(c.dir)
	}
	digest, id, err := c.stateFile()
	if err != nil {
		return false, err
	}
	if err := c.at("fence"); err != nil {
		return false, err
	}
	pending := fence{Generation: req.Generation, Deregistered: true, Pending: true, RemovedDigest: digest, RemovedFile: id}
	if err := c.writeFence(pending); err != nil {
		return false, err
	}
	return true, c.completeRemoval(req.Generation, digest != "")
}

// uniqueKeys reports whether data is a JSON object that names no key twice,
// ignoring case: encoding/json matches field names case-insensitively and
// keeps the last of repeated keys.
func uniqueKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	var seen []string
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		var value json.RawMessage
		if err != nil || !ok || slices.ContainsFunc(seen, func(s string) bool { return strings.EqualFold(s, key) }) ||
			dec.Decode(&value) != nil {
			return false
		}
		seen = append(seen, key)
	}
	return true
}

// sameTrust reports whether s sends a stored secret nowhere new: the stored
// registration has the same CA and every address of s. A registration with no
// recorded addresses or CA is changed.
func sameTrust(stored, s registrationSnapshot) bool {
	if len(stored.PVEAPIURLs) == 0 || stored.CAPEM == "" || stored.CAPEM != s.CAPEM {
		return false
	}
	held := make(map[string]bool, len(stored.PVEAPIURLs))
	for _, u := range stored.PVEAPIURLs {
		held[endpointKey(u)] = true
	}
	for _, u := range s.PVEAPIURLs {
		if !held[endpointKey(u)] {
			return false
		}
	}
	return true
}

func endpointKey(raw string) string { return strings.TrimSuffix(strings.ToLower(raw), "/") }

// verifyOtherEndpoints asks every address for the cluster name before the
// registration is stored, when there is more than one: a mixed set must not
// be accepted, an address that cannot answer is a typo to fix now, and a
// standalone node, which has no cluster row, cannot stand in a list.
func (c *Connection) verifyOtherEndpoints(ctx context.Context, s registrationSnapshot) error {
	if len(s.PVEAPIURLs) < 2 {
		return nil
	}
	transport, err := c.httpClient(s.CAPEM)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, endpoint := range s.PVEAPIURLs {
		client, err := pveclient.New(pveclient.Config{
			BaseURL: endpoint, TokenID: s.TokenID, Secret: pveclient.Secret(s.Token), HTTPClient: transport,
		})
		var rows []pveclient.ClusterStatus
		if err == nil {
			rows, err = client.ClusterStatus(ctx)
		}
		if err != nil {
			return &resource.Error{Code: resource.CodeUnavailable, Message: "registration self-check failed: pveApiUrls"}
		}
		if err := checkClusterNameInList(rows, s.ClusterName); err != nil {
			return err
		}
	}
	return nil
}

// Check reloads the state file and repeats the startup self-check.
func (c *Connection) Check(ctx context.Context) (*Backend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, data, err := c.registration()
	if err != nil {
		return nil, err
	}
	b, err := c.check(ctx, s)
	if err == nil {
		// A reload trusts the DR settings its registration checked and never
		// calls PBS, so PBS being down does not take the region down.
		dr, drData := c.storedDR(ctx)
		if dr != nil {
			b.pbs = dr.target()
		}
		digest := stateDigest(data, drData)
		if c.current != nil && c.digest == digest {
			return c.current, nil
		}
		c.current, c.digest = b, digest
	}
	return b, err
}

func (c *Connection) registration() (registrationSnapshot, []byte, error) {
	var s registrationSnapshot
	settled, err := c.finishPendingRemoval()
	if err != nil {
		return s, nil, err
	}
	if settled.Deregistered {
		return s, nil, ErrUnregistered
	}
	data, err := readStateFile(c.dir, registrationFile)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil, ErrUnregistered
	}
	if err != nil {
		return s, nil, errors.New("registration unreadable")
	}
	s, err = decodeState(data)
	if err != nil {
		if field := resource.AsError(err).Field; (field == "pveApiUrls" || field == "caPem") && s.Region == c.region {
			// s still holds the decoded tokens, so a re-registration may omit them.
			return s, nil, errNoEndpoints
		}
		return s, nil, errors.New("invalid registration")
	}
	if s.Region != c.region {
		return s, nil, errors.New("registration is for another region than this instance")
	}
	return s, data, nil
}

// readStateFile reads one state file: a private regular file, not a symlink,
// of at most maxRegistrationBytes. A missing file is os.ErrNotExist.
func readStateFile(dir, name string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	info, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, maxRegistrationBytes+1))
	if err := errors.Join(statErr, readErr, f.Close()); err != nil || len(data) > maxRegistrationBytes ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s unreadable", name)
	}
	return data, nil
}
