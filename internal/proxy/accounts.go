package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// RegistryAccounts reads role and region metadata from the admin registry.
// External IDs remain systemd credentials until the registry has an encrypted field.
type RegistryAccounts struct {
	Registry            *store.Registry
	CredentialDirectory string
}

// Account reads current metadata and its per-account external ID.
func (a RegistryAccounts) Account(ctx context.Context, id string) (Account, error) {
	v, err := a.Registry.AWSAccounts().Get(ctx, id)
	if err != nil {
		return Account{}, errors.New("proxy: account unavailable")
	}
	if filepath.Base(id) != id || a.CredentialDirectory == "" {
		return Account{}, errors.New("proxy: external ID unavailable")
	}
	b, err := os.ReadFile(filepath.Join(a.CredentialDirectory, "aws-external-id-"+id))
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return Account{}, errors.New("proxy: external ID unavailable")
	}
	return Account{RoleARN: v.RoleARN, Regions: v.AllowedRegions, ExternalID: strings.TrimSpace(string(b))}, nil
}

// SourceCredential reads only systemd's credential directory, never AWS environment or shared files.
func SourceCredential() (sigv4.Credential, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return sigv4.Credential{}, errors.New("proxy: systemd credentials required")
	}
	b, err := os.ReadFile(filepath.Join(dir, "aws-source"))
	var c struct{ AccessKey, Secret, SessionToken string }
	if err != nil || json.Unmarshal(b, &c) != nil {
		return sigv4.Credential{}, errors.New("proxy: source credentials unreadable")
	}
	out := sigv4.Credential{AccessKey: c.AccessKey, Secret: c.Secret, SessionToken: c.SessionToken}
	if !validCredential(out) {
		return sigv4.Credential{}, errors.New("proxy: source credentials rejected")
	}
	return out, nil
}

func validCredential(c sigv4.Credential) bool {
	for _, v := range []string{c.AccessKey, c.Secret} {
		low := strings.ToLower(v)
		if v == "" || strings.Contains(low, "example") || low == "secret" || low == "default" || low == "changeme" {
			return false
		}
	}
	return true
}
