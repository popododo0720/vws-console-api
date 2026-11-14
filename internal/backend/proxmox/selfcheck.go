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

type selfCheckError struct {
	check string
	cause error
}

func (e *selfCheckError) Error() string { return e.cause.Error() }
func (e *selfCheckError) Unwrap() error { return e.cause }

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
		return nil, &selfCheckError{check: "instance_types", cause: err}
	}
	if _, err := NewIDs(reg.ClusterName); err != nil {
		return nil, fmt.Errorf("proxmox: registration cluster_name: %w", err)
	}
	permissions, err := client.AccessPermissions(ctx, "")
	if err == nil && permissions == nil {
		err = errors.New("missing or null permission inventory")
	}
	if err != nil {
		return nil, &selfCheckError{check: "privileges", cause: fmt.Errorf("proxmox: check token permissions: %w", err)}
	}
	if err := checkSDN(ctx, client, cfg, permissions); err != nil {
		return nil, err
	}
	if cfg.ReadOnly {
		for path, privileges := range permissions {
			for privilege := range privileges {
				if forbiddenPrivilege(privilege) {
					return nil, &selfCheckError{
						check: "privileges", cause: fmt.Errorf("proxmox: read_only token holds %s on %s", privilege, path),
					}
				}
			}
		}
	} else {
		for path, privileges := range permissions {
			for privilege := range privileges {
				if forbiddenMutationPrivilege(path, privilege) {
					return nil, &selfCheckError{
						check: "privileges", cause: fmt.Errorf("proxmox: mutation token holds %s on %s", privilege, path),
					}
				}
			}
		}
	}
	status, err := client.ClusterStatus(ctx)
	if err != nil {
		return nil, &selfCheckError{check: "cluster_name", cause: fmt.Errorf("proxmox: check cluster_name: %w", err)}
	}
	if err := checkClusterName(status, reg.ClusterName); err != nil {
		return nil, err
	}
	pools := make([]string, 0, len(cfg.Pools)+1)
	for _, pool := range cfg.Pools {
		pools = append(pools, pool)
	}
	if cfg.Templates.Pool != "" {
		pools = append(pools, cfg.Templates.Pool)
	}
	if err := checkPools(ctx, client, pools); err != nil {
		return nil, &selfCheckError{check: "pools", cause: err}
	}
	if len(cfg.Storages) != 0 || cfg.SnippetsStorage != "" {
		rows, err := client.ClusterResources(ctx, pveclient.ResourceStorage)
		if err != nil {
			return nil, &selfCheckError{check: "storages", cause: fmt.Errorf("proxmox: check storages: %w", err)}
		}
		known := map[string]bool{}
		for _, row := range rows {
			if row.Type == "storage" {
				known[row.Storage] = true
			}
		}
		for volumeType, storage := range cfg.Storages {
			if storage == "" || !known[storage] {
				return nil, &selfCheckError{
					check: "storages", cause: fmt.Errorf("proxmox: storages.%s: unknown storage %q", volumeType, storage),
				}
			}
		}
		if cfg.SnippetsStorage != "" && !known[cfg.SnippetsStorage] {
			return nil, &selfCheckError{
				check: "storages", cause: fmt.Errorf("proxmox: snippets_storage: unknown storage %q", cfg.SnippetsStorage),
			}
		}
	}
	return &Backend{
		region: reg.Region.Name, cluster: reg.ClusterName, client: client, cfg: cfg, zones: reg.Region.Zones,
	}, nil
}

func checkSDN(ctx context.Context, c *pveclient.Client, cfg RegionConfig, permissions pveclient.Permissions) error {
	var zones []pveclient.SDNZone
	if cfg.SDNZone != "" {
		var err error
		zones, err = c.SDNZones(ctx)
		found := false
		for _, zone := range zones {
			found = found || zone.Zone == cfg.SDNZone
		}
		if err != nil {
			return &selfCheckError{check: "sdn_zone", cause: fmt.Errorf("proxmox: read sdn_zone: %w", err)}
		}
		if !found {
			return &selfCheckError{check: "sdn_zone", cause: fmt.Errorf("proxmox: unknown sdn_zone %q", cfg.SDNZone)}
		}
	}
	if cfg.ReadOnly {
		return nil
	}
	for path, privileges := range permissions {
		if _, held := privileges["SDN.Allocate"]; !held {
			continue
		}
		zonePath := "/sdn/zones/" + cfg.SDNZone
		if cfg.SDNZone == "" || (path != "/sdn" && path != zonePath && !strings.HasPrefix(path, zonePath+"/")) {
			return &selfCheckError{
				check: "privileges", cause: fmt.Errorf("proxmox: mutation token holds SDN.Allocate on %s", path),
			}
		}
		if path != "/sdn" {
			continue
		}
		probes := []string{"vwsprobe"}
		for _, zone := range zones {
			if zone.Zone != cfg.SDNZone {
				probes = append(probes, zone.Zone)
			}
		}
		for _, zone := range probes {
			probe := "/sdn/zones/" + zone
			held, err := c.AccessPermissions(ctx, probe)
			if err != nil {
				return &selfCheckError{
					check: "privileges", cause: fmt.Errorf("proxmox: unreadable SDN grant probe %s: %w", probe, err),
				}
			}
			if held[probe] == nil {
				return &selfCheckError{check: "privileges", cause: fmt.Errorf("proxmox: missing SDN grant probe %s", probe)}
			}
			if _, allocated := held[probe]["SDN.Allocate"]; allocated {
				return &selfCheckError{check: "privileges", cause: fmt.Errorf("proxmox: propagated SDN.Allocate on %s", probe)}
			}
		}
	}
	return nil
}

// checkBackup admits only the privileges needed for stop-mode disk exports.
func checkBackup(ctx context.Context, c *pveclient.Client, cfg RegionConfig) error {
	if cfg.ReadOnly {
		return &selfCheckError{
			check: "backup_privileges", cause: errors.New("proxmox: read_only region takes no backup token"),
		}
	}
	permissions, err := c.AccessPermissions(ctx, "")
	if err == nil && permissions == nil {
		err = errors.New("missing or null permission inventory")
	}
	if err != nil {
		return &selfCheckError{
			check: "backup_privileges", cause: fmt.Errorf("proxmox: check backup token permissions: %w", err),
		}
	}
	storage := false
	for path, privileges := range permissions {
		for privilege := range privileges {
			switch privilege {
			case "VM.Backup":
			case "Datastore.AllocateSpace":
				storage = storage || strings.HasPrefix(path, "/storage/") && len(path) > len("/storage/")
			default:
				return &selfCheckError{
					check: "backup_privileges", cause: fmt.Errorf("proxmox: backup token holds %s on %s", privilege, path),
				}
			}
		}
	}
	for _, pool := range cfg.Pools {
		path := "/pool/" + pool
		held, err := c.AccessPermissions(ctx, path)
		if err != nil {
			return &selfCheckError{
				check: "backup_privileges", cause: fmt.Errorf("proxmox: check backup pool %s: %w", path, err),
			}
		}
		if _, ok := held[path]["VM.Backup"]; !ok {
			return &selfCheckError{
				check: "backup_privileges", cause: fmt.Errorf("proxmox: backup token lacks VM.Backup on %s", path),
			}
		}
	}
	if !storage {
		return &selfCheckError{
			check: "backup_privileges",
			cause: errors.New("proxmox: backup token lacks Datastore.AllocateSpace on /storage/<id>"),
		}
	}
	return nil
}

// checkFirewall admits a token that holds Sys.Modify and Sys.Audit on / and
// nothing else: PVE checks every cluster firewall group write as Sys.Modify on /.
func checkFirewall(ctx context.Context, c *pveclient.Client, cfg RegionConfig) error {
	if cfg.ReadOnly {
		return &selfCheckError{
			check: "firewall_privileges", cause: errors.New("proxmox: read_only region takes no firewall token"),
		}
	}
	permissions, err := c.AccessPermissions(ctx, "")
	if err == nil && permissions == nil {
		err = errors.New("missing or null permission inventory")
	}
	if err != nil {
		return &selfCheckError{
			check: "firewall_privileges", cause: fmt.Errorf("proxmox: check firewall token permissions: %w", err),
		}
	}
	for path, privileges := range permissions {
		for privilege := range privileges {
			if privilege != "Sys.Modify" && privilege != "Sys.Audit" {
				return &selfCheckError{
					check: "firewall_privileges", cause: fmt.Errorf("proxmox: firewall token holds %s on %s", privilege, path),
				}
			}
		}
	}
	for _, privilege := range []string{"Sys.Modify", "Sys.Audit"} {
		if _, held := permissions["/"][privilege]; !held {
			return &selfCheckError{
				check: "firewall_privileges", cause: fmt.Errorf("proxmox: firewall token lacks %s on /", privilege),
			}
		}
	}
	return nil
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
