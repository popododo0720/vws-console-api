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
	cfg.ReadOnly = true
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
	client, err := pveclient.New(pveclient.Config{
		BaseURL: c.endpoint, TokenID: s.TokenID, Secret: s.Token, HTTPClient: c.transport,
	})
	if err != nil {
		return nil, errors.New("invalid PVE connection")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := New(ctx, client, Registration{
		Region: backend.ProxmoxRegion{Name: s.Region, Zones: s.Zones}, ClusterName: s.ClusterName,
	}, c.config)
	if err != nil && resource.AsError(err).Code != resource.CodeConflict {
		return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "registration self-check failed"}
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
	if reuse {
		data, err := os.ReadFile(c.path)
		if errors.Is(err, os.ErrNotExist) {
			return resource.Invalid("token", "required for first registration")
		}
		if err != nil || len(data) > maxRegistrationIdentityBytes {
			return errors.New("registration unreadable")
		}
		stored, err := decodeRegistration(data)
		if err != nil || stored.Token != "" {
			return errors.New("invalid registration identity")
		}
		token, err := c.Helper.ReadToken(ctx)
		if err != nil {
			return err
		}
		s.Token = pveclient.Secret(token)
		if stored.Fingerprint != tokenFingerprint(s.Token) {
			return resource.Invalid("token", "stored registration token mismatch")
		}
	}
	if _, err := c.check(ctx, s); err != nil {
		return err
	}
	token := []byte(s.Token)
	s.Fingerprint, s.Token = tokenFingerprint(s.Token), ""
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
	defer func() {
		if err := c.Helper.Unlock(context.WithoutCancel(ctx), "registration"); err != nil {
			slog.WarnContext(ctx, "registration unlock failed")
		}
	}()
	if reuse {
		return c.Helper.WriteRegistration(ctx, identity)
	}
	var previous []byte
	if _, statErr := os.Stat(c.path); !errors.Is(statErr, os.ErrNotExist) {
		if statErr != nil {
			return errors.New("registration unreadable")
		}
		previous, err = c.Helper.ReadToken(ctx)
		if err != nil {
			return err
		}
	}
	err = c.Helper.WriteToken(ctx, token)
	if err == nil {
		err = c.Helper.WriteRegistration(ctx, identity)
	}
	if err != nil {
		return errors.Join(err, c.Helper.WriteToken(context.WithoutCancel(ctx), previous))
	}
	return nil
}

// Check reloads the shared files and repeats the startup self-check.
func (c *Connection) Check(ctx context.Context) (*Backend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(c.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("unregistered")
	}
	if err != nil {
		return nil, errors.New("registration unreadable")
	}
	info, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, maxRegistrationIdentityBytes+1))
	if err := errors.Join(statErr, readErr, f.Close()); err != nil || len(data) > maxRegistrationIdentityBytes ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("registration unreadable")
	}
	s, err := decodeRegistration(data)
	if err != nil || s.Token != "" {
		return nil, errors.New("invalid registration identity")
	}
	token, err := c.Helper.ReadToken(ctx)
	if err != nil {
		return nil, err
	}
	s.Token = pveclient.Secret(token)
	if s.Fingerprint != tokenFingerprint(s.Token) {
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
