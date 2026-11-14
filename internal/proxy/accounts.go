package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// RegistryAccounts reads role and region metadata from the admin registry.
// Forwarding external IDs remain systemd credentials; sealed registry values serve admin diagnostics.
type RegistryAccounts struct {
	Registry            *store.Registry
	CredentialDirectory string
}

// Account selects the sole mapped account allowing the requested region.
func (a RegistryAccounts) Account(ctx context.Context, project, region string) (Account, error) {
	return a.account(ctx, project, region, "")
}

// CostAccount selects an explicitly mapped account for the global Cost Explorer service.
func (a RegistryAccounts) CostAccount(ctx context.Context, project, id string) (Account, error) {
	if !accountID(id) {
		return Account{}, errors.New("proxy: account unavailable")
	}
	return a.account(ctx, project, "", id)
}

func (a RegistryAccounts) account(ctx context.Context, project, region, requested string) (Account, error) {
	if !accountID(project) {
		return Account{}, errors.New("proxy: account unavailable")
	}
	mapping, err := a.Registry.Projects().Get(ctx, project)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Account{}, fmt.Errorf("proxy: project unavailable: %w", store.ErrNotFound)
		}
		return Account{}, errors.New("proxy: account unavailable")
	}
	out := Account{MappingVersion: int64(mapping.Version)}
	var selected store.AWSAccount
	for _, id := range mapping.AWSAccounts {
		if requested != "" && id != requested {
			continue
		}
		if !accountID(id) {
			return out, errors.New("proxy: account unavailable")
		}
		v, err := a.Registry.AWSAccounts().Get(ctx, id)
		if err != nil {
			return out, errors.New("proxy: account unavailable")
		}
		if requested == v.ID || requested == "" && slices.Contains(v.AllowedRegions, region) {
			if selected.ID != "" {
				return out, errors.New("proxy: ambiguous account mapping")
			}
			selected = v
		}
	}
	if selected.ID == "" {
		return out, errors.New("proxy: account unavailable")
	}
	if a.CredentialDirectory == "" {
		return out, errors.New("proxy: external ID unavailable")
	}
	b, err := os.ReadFile(filepath.Join(a.CredentialDirectory, "aws-external-id-"+selected.ID))
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return out, errors.New("proxy: external ID unavailable")
	}
	out.ID, out.RoleARN, out.Regions = selected.ID, selected.RoleARN, selected.AllowedRegions
	out.ExternalID = strings.TrimSpace(string(b))
	return out, nil
}

// accountID reports a 12-digit AWS account ID. It becomes part of a
// credential file name, so nothing else may reach the filesystem.
func accountID(id string) bool {
	if len(id) != 12 {
		return false
	}
	for i := range len(id) {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
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
