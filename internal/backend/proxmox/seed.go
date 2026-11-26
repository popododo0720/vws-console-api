package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
)

// checkSeed is the self-check of seed_storage, run by New when it is set and
// the region is not read_only. A failure is the "seed_storage" check:
//  1. the state directory is set;
//  2. /cluster/resources lists the storage, and every row of it lists iso
//     content; PVE lists a storage only to a token with Datastore.Audit on
//     it, so this also checks that privilege;
//  3. the token holds Datastore.AllocateTemplate on /storage/<seed_storage>,
//     and no other listed path holds it;
//  4. pooled (from checkPools) holds VM.Config.CDROM on each /pool/<id> of pools;
//  5. every static subnet has 1 to 3 IPv4 nameservers, and no other subnet
//     has any.
func checkSeed(ctx context.Context, c *pveclient.Client, cfg RegionConfig,
	permissions, pooled pveclient.Permissions,
) error {
	if cfg.StateDir == "" {
		return errors.New("proxmox: seed_storage needs the daemon state directory")
	}
	rows, err := c.ClusterResources(ctx, pveclient.ResourceStorage)
	if err != nil {
		return fmt.Errorf("proxmox: check seed_storage: %w", err)
	}
	found := false
	for _, row := range rows {
		if row.Type != "storage" || row.Storage != cfg.SeedStorage {
			continue
		}
		found = true
		if !slices.Contains(strings.Split(row.Content, ","), "iso") {
			return fmt.Errorf("proxmox: seed_storage %q on %s has no iso content", cfg.SeedStorage, row.Node)
		}
	}
	if !found {
		return fmt.Errorf("proxmox: unknown seed_storage %q, or the token lacks Datastore.Audit on it", cfg.SeedStorage)
	}
	seedPath := "/storage/" + cfg.SeedStorage
	if _, held := permissions[seedPath]["Datastore.AllocateTemplate"]; !held {
		return fmt.Errorf("proxmox: token lacks Datastore.AllocateTemplate on %s", seedPath)
	}
	for path, privileges := range permissions {
		if _, held := privileges["Datastore.AllocateTemplate"]; held && path != seedPath {
			return fmt.Errorf("proxmox: token holds Datastore.AllocateTemplate on %s", path)
		}
	}
	for _, pool := range cfg.Pools {
		path := "/pool/" + pool
		if _, ok := pooled[path]["VM.Config.CDROM"]; !ok {
			return fmt.Errorf("proxmox: token lacks VM.Config.CDROM on %s", path)
		}
	}
	for name, subnet := range cfg.Subnets {
		static := subnet.Mode == "" || subnet.Mode == "static"
		if !static && len(subnet.Nameservers) != 0 {
			return fmt.Errorf("proxmox: subnets.%s: nameservers are for static subnets only", name)
		}
		if static && (len(subnet.Nameservers) == 0 || len(subnet.Nameservers) > 3) {
			return fmt.Errorf("proxmox: subnets.%s: a static subnet needs 1 to 3 nameservers", name)
		}
		for _, ns := range subnet.Nameservers {
			if addr, err := netip.ParseAddr(ns); err != nil || !addr.Is4() || addr.IsUnspecified() {
				return fmt.Errorf("proxmox: subnets.%s: nameserver %q is not an IPv4 address", name, ns)
			}
		}
	}
	return nil
}
