package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Registration is identity supplied by the admin registration, separate from region.yaml.
type Registration struct {
	Region      backend.ProxmoxRegion
	ClusterName string
}

// Identity returns the checked identity, without credentials.
func Identity(b *Backend) Registration {
	return Registration{
		Region: backend.ProxmoxRegion{Name: b.region, Zones: b.zones}, ClusterName: b.cluster,
	}
}

// New checks configuration against PVE before exposing a backend.
func New(ctx context.Context, client *pveclient.Client, reg Registration, cfg RegionConfig) (*Backend, error) {
	if client == nil {
		return nil, errors.New("proxmox: missing PVE client")
	}
	if reg.Region.Name == "" {
		return nil, errors.New("proxmox: registration region name is required")
	}
	if err := validateInstanceTypes(cfg); err != nil {
		return nil, err
	}
	if _, err := NewIDs(reg.ClusterName); err != nil {
		return nil, fmt.Errorf("proxmox: registration cluster_name: %w", err)
	}
	permissions, err := client.AccessPermissions(ctx, "")
	if err == nil && permissions == nil {
		err = errors.New("missing or null permission inventory")
	}
	if err != nil {
		return nil, fmt.Errorf("proxmox: check token permissions: %w", err)
	}
	if cfg.ReadOnly {
		for path, privileges := range permissions {
			for privilege := range privileges {
				if forbiddenPrivilege(privilege) {
					return nil, fmt.Errorf("proxmox: read_only token holds %s on %s", privilege, path)
				}
			}
		}
	} else {
		for path, privileges := range permissions {
			for privilege := range privileges {
				if forbiddenMutationPrivilege(path, privilege) {
					return nil, fmt.Errorf("proxmox: mutation token holds %s on %s", privilege, path)
				}
			}
		}
	}
	status, err := client.ClusterStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: check cluster_name: %w", err)
	}
	if err := checkClusterName(status, reg.ClusterName); err != nil {
		return nil, err
	}
	if len(cfg.Storages) != 0 || cfg.SnippetsStorage != "" {
		rows, err := client.ClusterResources(ctx, pveclient.ResourceStorage)
		if err != nil {
			return nil, fmt.Errorf("proxmox: check storages: %w", err)
		}
		known := map[string]bool{}
		for _, row := range rows {
			if row.Type == "storage" {
				known[row.Storage] = true
			}
		}
		for volumeType, storage := range cfg.Storages {
			if storage == "" || !known[storage] {
				return nil, fmt.Errorf("proxmox: storages.%s: unknown storage %q", volumeType, storage)
			}
		}
		if cfg.SnippetsStorage != "" && !known[cfg.SnippetsStorage] {
			return nil, fmt.Errorf("proxmox: snippets_storage: unknown storage %q", cfg.SnippetsStorage)
		}
	}
	return &Backend{
		region: reg.Region.Name, cluster: reg.ClusterName, client: client, cfg: cfg, zones: reg.Region.Zones,
	}, nil
}

func forbiddenPrivilege(p string) bool {
	return !strings.HasSuffix(p, ".Audit")
}

func forbiddenMutationPrivilege(path, privilege string) bool {
	if (path == "/" || path == "/vms") &&
		strings.HasPrefix(privilege, "VM.") && !strings.HasSuffix(privilege, ".Audit") {
		return true
	}
	switch privilege {
	case "Permissions.Modify", "Pool.Allocate", "Sys.Modify", "Datastore.Allocate",
		"VM.Migrate", "VM.Snapshot.Rollback", "VM.GuestAgent.Unrestricted":
		return true
	default:
		return false
	}
}

// Standalone PVE has no cluster row and keeps the registered identity.
func checkClusterName(status []pveclient.ClusterStatus, registered string) error {
	for _, row := range status {
		if row.Type == "cluster" && row.Name != registered {
			return &resource.Error{Code: resource.CodeConflict, Message: "cluster_name differs from registration"}
		}
	}
	return nil
}
