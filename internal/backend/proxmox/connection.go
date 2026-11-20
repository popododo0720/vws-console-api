package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// errNoEndpoints is the state of a registration file written before it carried
// pveApiUrls and caPem.
var errNoEndpoints = errors.New("registration has no valid pveApiUrls and caPem; register the region again")

// maxRegistrationBytes bounds the registration request and the state file.
const (
	maxRegistrationBytes = 65 << 10
	registrationFile     = "registration.json"
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

	FirewallTokenID string `json:"firewallTokenId,omitempty"`
	FirewallToken   string `json:"firewallToken,omitempty"`

	BackupTokenID string `json:"backupTokenId,omitempty"`
	BackupToken   string `json:"backupToken,omitempty"`
}

// Connection serves the one region this instance is named for. Its state is
// one 0600 file under the state directory; the token sits inside it.
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
	if err := removeStaleTemps(stateDir, registrationFile); err != nil {
		return nil, err
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

func decodeRegistration(data []byte) (registrationSnapshot, error) {
	var s registrationSnapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, resource.Invalid("registration", "invalid JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return s, resource.Invalid("registration", "expected one JSON document")
	}
	if !registrationRegion.MatchString(s.Region) || !registrationCluster.MatchString(s.ClusterName) ||
		!registrationTokenID.MatchString(s.TokenID) || len(s.Zones) > 26 {
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
		if message := resource.RegistrationFailureMessage(err); message != "" {
			return nil, &resource.Error{Code: resource.CodeUnavailable, Message: message}
		}
		message := "registration self-check failed"
		var failure *selfCheckError
		if errors.As(err, &failure) {
			message += ": " + failure.check
		}
		return nil, &resource.Error{Code: resource.CodeUnavailable, Message: message}
	}
	return b, err
}

// Register validates against PVE, then replaces the state file. The
// in-process mutex serializes registrations and reads; one daemon owns the file.
func (c *Connection) Register(ctx context.Context, data json.RawMessage) error {
	s, err := decodeRegistration(data)
	if err != nil {
		return err
	}
	if s.Region != c.region {
		return resource.Invalid("region", "registration is for another region than this instance")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.Token == "" || s.FirewallTokenID != "" && s.FirewallToken == "" ||
		s.BackupTokenID != "" && s.BackupToken == "" {
		stored, _, err := c.registration()
		if err != nil && err.Error() != "unregistered" && !errors.Is(err, errNoEndpoints) {
			return err
		}
		// A stored secret goes only to the destination that already held it.
		unchanged := sameTrust(stored, s)
		if s.Token == "" {
			if stored.TokenID != s.TokenID || stored.Token == "" {
				return resource.Invalid("token", "required for first registration")
			}
			if !unchanged {
				return resource.Invalid("token", "required when caPem or pveApiUrls change")
			}
			s.Token = stored.Token
		}
		if s.FirewallTokenID != "" && s.FirewallToken == "" {
			if !unchanged {
				return resource.Invalid("firewallToken", "required when caPem or pveApiUrls change")
			}
			if stored.FirewallTokenID != s.FirewallTokenID || stored.FirewallToken == "" {
				return resource.Invalid("firewallToken", "required for a new firewall token")
			}
			s.FirewallToken = stored.FirewallToken
		}
		if s.BackupTokenID != "" && s.BackupToken == "" {
			if !unchanged {
				return resource.Invalid("backupToken", "required when caPem or pveApiUrls change")
			}
			if stored.BackupTokenID != s.BackupTokenID || stored.BackupToken == "" {
				return resource.Invalid("backupToken", "required for a new backup token")
			}
			s.BackupToken = stored.BackupToken
		}
	}
	if _, err := c.check(ctx, s); err != nil {
		return err
	}
	if err := c.verifyOtherEndpoints(ctx, s); err != nil {
		return err
	}
	state, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode registration: %w", err)
	}
	if len(state) > maxRegistrationBytes {
		return resource.Invalid("registration", "serialized registration exceeds 65 KiB")
	}
	if err := writeFileAtomic(c.dir, registrationFile, state, nil); err != nil {
		return fmt.Errorf("persist registration: %w", err)
	}
	return nil
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
		digest := sha256.Sum256(data)
		if c.current != nil && c.digest == digest {
			return c.current, nil
		}
		c.current, c.digest = b, digest
	}
	return b, err
}

func (c *Connection) registration() (registrationSnapshot, []byte, error) {
	var s registrationSnapshot
	f, err := os.OpenFile(filepath.Join(c.dir, registrationFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil, errors.New("unregistered")
	}
	if err != nil {
		return s, nil, errors.New("registration unreadable")
	}
	info, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, maxRegistrationBytes+1))
	if err := errors.Join(statErr, readErr, f.Close()); err != nil || len(data) > maxRegistrationBytes ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return s, nil, errors.New("registration unreadable")
	}
	s, err = decodeRegistration(data)
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
