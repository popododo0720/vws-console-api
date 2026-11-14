package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/regionhelper"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Persisted identity adds fingerprint metadata to a request bounded to 64 KiB.
const maxRegistrationIdentityBytes = 65 << 10

// tokenUnreadable is the readiness reason when the token file the identity
// names is absent or unreadable, e.g. a node still on the unsuffixed layout;
// one registration PUT with the token repairs it.
const tokenUnreadable = "registration token unreadable"

var (
	registrationRegion  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	registrationCluster = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$`)
	registrationTokenID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`)
	registrationSecret  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,512}$`)
)

type registrationSnapshot struct {
	Region string `json:"region"`
	//nolint:tagliatelle // The registration protocol names cluster_name.
	ClusterName string           `json:"cluster_name"`
	Zones       []backend.Zone   `json:"zones"`
	TokenID     string           `json:"tokenId"`
	Token       pveclient.Secret `json:"token,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"`

	FirewallTokenID     string           `json:"firewallTokenId,omitempty"`
	FirewallToken       pveclient.Secret `json:"firewallToken,omitempty"`
	FirewallFingerprint string           `json:"firewallFingerprint,omitempty"`
}

// Connection loads registration identity and encrypted credentials from pmxcfs.
type Connection struct {
	Helper         regionhelper.Client
	mu             sync.Mutex
	config         RegionConfig
	path, endpoint string
	transport      *http.Client
	current        *Backend
	digest         [32]byte
}

// Open loads node-local configuration; registration may arrive after startup.
func Open(configPath, registrationPath, endpoint string, transport *http.Client) (*Connection, error) {
	cfg, err := LoadRegion(configPath)
	if err != nil {
		return nil, err
	}
	return &Connection{config: cfg, path: registrationPath, endpoint: endpoint, transport: transport}, nil
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
	if s.FirewallTokenID == "" && (s.FirewallToken != "" || s.FirewallFingerprint != "") ||
		s.FirewallTokenID != "" && (!registrationTokenID.MatchString(s.FirewallTokenID) || s.FirewallTokenID == s.TokenID) {
		return s, resource.Invalid("firewallTokenId", "expected a second user@realm!token")
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

func tokenFingerprint(token pveclient.Secret) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
}

func (c *Connection) check(ctx context.Context, s registrationSnapshot) (*Backend, error) {
	if !registrationSecret.MatchString(string(s.Token)) {
		return nil, resource.Invalid("token", "expected 1-512 token characters")
	}
	if s.FirewallTokenID != "" && !registrationSecret.MatchString(string(s.FirewallToken)) {
		return nil, resource.Invalid("firewallToken", "expected 1-512 token characters")
	}
	client, err := pveclient.New(pveclient.Config{
		BaseURL: c.endpoint, TokenID: s.TokenID, Secret: s.Token, HTTPClient: c.transport,
	})
	if err != nil {
		return nil, errors.New("invalid PVE connection")
	}
	var firewall *pveclient.Client
	if s.FirewallTokenID != "" {
		firewall, err = pveclient.New(pveclient.Config{
			BaseURL: c.endpoint, TokenID: s.FirewallTokenID, Secret: s.FirewallToken, HTTPClient: c.transport,
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
	if err == nil && firewall != nil {
		if err = checkFirewall(ctx, firewall, c.config); err == nil {
			b.firewall = firewall
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

// Register validates against PVE before asking the helper to persist anything.
func (c *Connection) Register(ctx context.Context, data json.RawMessage) error {
	s, err := decodeRegistration(data)
	if err != nil {
		return err
	}
	if s.Fingerprint != "" {
		return resource.Invalid("fingerprint", "server managed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	reuse := s.Token == ""
	reuseFirewall := s.FirewallTokenID != "" && s.FirewallToken == ""
	if reuse || reuseFirewall {
		field := "token"
		if !reuse {
			field = "firewallToken"
		}
		data, err := os.ReadFile(c.path)
		if errors.Is(err, os.ErrNotExist) {
			return resource.Invalid(field, "required for first registration")
		}
		if err != nil || len(data) > maxRegistrationIdentityBytes {
			return errors.New("registration unreadable")
		}
		stored, err := decodeRegistration(data)
		if err != nil || stored.Token != "" || stored.FirewallToken != "" {
			return errors.New("invalid registration identity")
		}
		if reuse {
			if s.Token, err = c.storedToken(ctx, "token", stored.Fingerprint); err != nil {
				return err
			}
		}
		if reuseFirewall {
			if stored.FirewallTokenID != s.FirewallTokenID {
				return resource.Invalid("firewallToken", "required for a new firewall token")
			}
			if s.FirewallToken, err = c.storedToken(ctx, "firewallToken", stored.FirewallFingerprint); err != nil {
				return err
			}
		}
	}
	if _, err := c.check(ctx, s); err != nil {
		return err
	}
	writes := map[string][]byte{}
	if !reuse {
		writes[tokenFingerprint(s.Token)] = []byte(s.Token)
	}
	if s.FirewallTokenID != "" {
		s.FirewallFingerprint = tokenFingerprint(s.FirewallToken)
		if !reuseFirewall {
			writes[s.FirewallFingerprint] = []byte(s.FirewallToken)
		}
	}
	s.Fingerprint, s.Token, s.FirewallToken = tokenFingerprint(s.Token), "", ""
	identity, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode registration identity: %w", err)
	}
	if len(identity) > maxRegistrationIdentityBytes {
		return resource.Invalid("registration", "serialized identity exceeds 65 KiB")
	}
	if err := c.Helper.Lock(ctx, "registration"); err != nil {
		return &resource.Error{Code: resource.CodeConflict, Message: "registration write in progress"}
	}
	var cleanup []string
	defer func() {
		if err := c.Helper.Unlock(context.WithoutCancel(ctx), "registration"); err != nil {
			slog.WarnContext(ctx, "registration unlock failed")
		}
		for _, fingerprint := range cleanup {
			if err := c.Helper.DeleteToken(context.WithoutCancel(ctx), fingerprint); err != nil {
				slog.WarnContext(ctx, "previous registration token cleanup failed")
			}
		}
	}()
	var old registrationSnapshot
	if reuse || reuseFirewall {
		if old, _, err = c.registration(); err != nil {
			return err
		}
		if reuse && old.Fingerprint != s.Fingerprint || reuseFirewall && old.FirewallFingerprint != s.FirewallFingerprint {
			return &resource.Error{Code: resource.CodeConflict, Message: "registration changed during self-check"}
		}
	} else {
		previous, err := os.ReadFile(c.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("registration unreadable")
		}
		if err == nil {
			if old, err = decodeRegistration(previous); err != nil {
				return err
			}
		}
	}
	for fingerprint, token := range writes {
		if err := c.Helper.WriteToken(ctx, fingerprint, token); err != nil {
			return err
		}
	}
	err = c.Helper.WriteRegistration(ctx, identity)
	if err != nil {
		current, _, readErr := c.registration()
		if readErr != nil || current.Fingerprint != s.Fingerprint || current.FirewallFingerprint != s.FirewallFingerprint {
			return err
		}
	}
	for _, fingerprint := range []string{old.Fingerprint, old.FirewallFingerprint} {
		if fingerprint != "" && fingerprint != s.Fingerprint && fingerprint != s.FirewallFingerprint {
			cleanup = append(cleanup, fingerprint)
		}
	}
	return err
}

func (c *Connection) storedToken(ctx context.Context, field, fingerprint string) (pveclient.Secret, error) {
	if fingerprint == "" {
		return "", resource.Invalid(field, "required for first registration")
	}
	token, err := c.Helper.ReadToken(ctx, fingerprint)
	if err != nil {
		return "", err
	}
	if tokenFingerprint(pveclient.Secret(token)) != fingerprint {
		return "", resource.Invalid(field, "stored registration token mismatch")
	}
	return pveclient.Secret(token), nil
}

func (c *Connection) readTokens(ctx context.Context, s *registrationSnapshot) error {
	token, err := c.Helper.ReadToken(ctx, s.Fingerprint)
	if err != nil {
		return err
	}
	s.Token = pveclient.Secret(token)
	if s.FirewallFingerprint != "" {
		token, err = c.Helper.ReadToken(ctx, s.FirewallFingerprint)
		s.FirewallToken = pveclient.Secret(token)
	}
	return err
}

// Check reloads the shared files and repeats the startup self-check.
func (c *Connection) Check(ctx context.Context) (*Backend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, data, err := c.registration()
	if err != nil {
		return nil, err
	}
	if err := c.readTokens(ctx, &s); err != nil {
		// A writer may have committed and collected this reader's old token.
		next, identity, readErr := c.registration()
		if readErr != nil {
			return nil, readErr
		}
		if next.Fingerprint == s.Fingerprint && next.FirewallFingerprint == s.FirewallFingerprint {
			return nil, errors.New(tokenUnreadable)
		}
		s, data = next, identity
		if err := c.readTokens(ctx, &s); err != nil {
			return nil, errors.New(tokenUnreadable)
		}
	}
	if s.Fingerprint != tokenFingerprint(s.Token) ||
		s.FirewallFingerprint != "" && s.FirewallFingerprint != tokenFingerprint(s.FirewallToken) {
		return nil, errors.New("registration token mismatch")
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
	f, err := os.OpenFile(c.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil, errors.New("unregistered")
	}
	if err != nil {
		return s, nil, errors.New("registration unreadable")
	}
	info, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, maxRegistrationIdentityBytes+1))
	if err := errors.Join(statErr, readErr, f.Close()); err != nil || len(data) > maxRegistrationIdentityBytes ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return s, nil, errors.New("registration unreadable")
	}
	s, err = decodeRegistration(data)
	if err != nil || s.Token != "" {
		return s, nil, errors.New("invalid registration identity")
	}
	return s, data, nil
}
