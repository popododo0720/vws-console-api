package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RGWKey stores only ciphertext; both credential fields are write-only.
type RGWKey struct {
	Project string        `json:"project"`
	Sealed  secret.Sealed `json:"sealed"`
	Version Version       `json:"-"`
}

func (r *RGWKey) name() string         { return r.Project }
func (r *RGWKey) version() Version     { return r.Version }
func (r *RGWKey) setVersion(v Version) { r.Version = v }

// RGWKeys is the versioned collection of encrypted project credentials.
func (g *Registry) RGWKeys() Collection[RGWKey, *RGWKey] {
	return Collection[RGWKey, *RGWKey]{b: g.b, kind: "rgw-keys/"}
}

// SealRGWKey encrypts the access key and secret with a purpose-bound project AAD.
func SealRGWKey(k *secret.Key, project resource.AccountID, access, value string) (RGWKey, error) {
	if k == nil || project.IsZero() || access == "" || value == "" ||
		len(access) > 128 || len(value) > 256 ||
		strings.ContainsAny(access, "/ ,") || strings.ContainsFunc(access+value, unicode.IsControl) {
		return RGWKey{}, resource.Invalid("rgwKey", "invalid credentials or missing KEK")
	}
	data, err := json.Marshal([]string{access, value})
	if err != nil {
		return RGWKey{}, fmt.Errorf("encode RGW credentials: %w", err)
	}
	sealed, err := k.Seal(data, "rgw:"+project.String())
	if err != nil {
		return RGWKey{}, fmt.Errorf("seal RGW credentials: %w", err)
	}
	return RGWKey{Project: project.String(), Sealed: sealed}, nil
}

// OpenRGWKey is for trusted signing callers, never public registry responses.
func (g *Registry) OpenRGWKey(ctx context.Context, k *secret.Key, project resource.AccountID) (string, string, error) {
	r, err := g.RGWKeys().Get(ctx, project.String())
	if err != nil {
		return "", "", err
	}
	if k == nil || r.Project != project.String() {
		return "", "", resource.Denied("RGW credentials unavailable")
	}
	data, err := k.Open(r.Sealed, "rgw:"+project.String())
	if err != nil {
		return "", "", fmt.Errorf("open RGW credentials: %w", err)
	}
	var pair []string
	if err := json.Unmarshal(data, &pair); err != nil || len(pair) != 2 || pair[0] == "" || pair[1] == "" {
		return "", "", resource.Invalid("rgwKey", "malformed stored credentials")
	}
	return pair[0], pair[1], nil
}
