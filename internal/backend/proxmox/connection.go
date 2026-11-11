package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
)

// The registration names a region as design.md does (pve-seoul-1), a PVE
// cluster, and a PVE API token id, user@realm!name.
var (
	registrationRegion  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	registrationCluster = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62})$`)
	registrationTokenID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`)
)

// Connection keeps PVE credentials and transport inside the Proxmox boundary.
type Connection struct {
	client *pveclient.Client
	reg    Registration
	config RegionConfig
}

// Open reads a private registration snapshot supplied outside region.yaml.
// Phase one consumes a decrypted snapshot; #757 owns encrypted storage and its helper.
func Open(configPath, registrationPath, endpoint string, transport *http.Client) (_ *Connection, err error) {
	cfg, err := LoadRegion(configPath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(registrationPath)
	if err != nil {
		return nil, fmt.Errorf("open registration: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close registration: %w", closeErr))
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat registration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return nil, errors.New("registration must be a private regular file under 64 KiB")
	}
	var snapshot struct {
		Region      string           `json:"region"`
		ClusterName string           `json:"clusterName"`
		TokenID     string           `json:"tokenId"`
		Token       pveclient.Secret `json:"token"`
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		// Decoder errors can include an offending secret value.
		return nil, errors.New("invalid registration snapshot")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("registration must contain one JSON document")
	}
	switch {
	case !registrationRegion.MatchString(snapshot.Region):
		return nil, errors.New("registration region must be 1-63 lowercase letters, digits or hyphens")
	case !registrationCluster.MatchString(snapshot.ClusterName):
		return nil, errors.New("registration clusterName must be 1-63 letters, digits, dots, underscores or hyphens")
	case !registrationTokenID.MatchString(snapshot.TokenID):
		return nil, errors.New("registration tokenId must be user@realm!name within PVE's character set")
	}
	client, err := pveclient.New(pveclient.Config{
		BaseURL: endpoint, TokenID: snapshot.TokenID, Secret: snapshot.Token, HTTPClient: transport,
	})
	if err != nil {
		return nil, errors.New("invalid PVE connection in registration")
	}
	cfg.ReadOnly = true
	return &Connection{client: client, config: cfg, reg: Registration{
		Region: backend.ProxmoxRegion{Name: snapshot.Region}, ClusterName: snapshot.ClusterName,
	}}, nil
}

// Check repeats the startup self-check, including PVE reachability and identity.
func (c *Connection) Check(ctx context.Context) (*Backend, error) {
	return New(ctx, c.client, c.reg, c.config)
}

// Identity returns the registered region and cluster, without credentials.
func (c *Connection) Identity() Registration { return c.reg }
