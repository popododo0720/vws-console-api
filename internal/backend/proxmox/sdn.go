package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type sdnMarker struct{ cidr, pool, fp string }

func (m sdnMarker) alias() string {
	return fmt.Sprintf("vws:v=1 cidr=%s pool=%s fp=%s", m.cidr, m.pool, m.fp)
}

func readSDNMarker(alias string) (sdnMarker, bool) {
	var m sdnMarker
	_, err := fmt.Sscanf(alias, "vws:v=1 cidr=%s pool=%s fp=%s", &m.cidr, &m.pool, &m.fp)
	p, parseErr := netip.ParsePrefix(m.cidr)
	return m, err == nil && parseErr == nil && CheckVPCCIDR(p) == nil && launchHex(m.fp, 16) && m.alias() == alias
}

type sdnVPC struct {
	row    pveclient.SDNVNet
	marker sdnMarker
	vpc    resource.Vpc
}

func (b *Backend) sdnVPCs(ctx context.Context, s backend.Scope) ([]sdnVPC, error) {
	if b.cfg.SDNZone == "" {
		return nil, nil
	}
	rows, err := b.client.SDNVNets(ctx)
	if err != nil {
		return nil, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return nil, err
	}
	var out []sdnVPC
	for _, row := range rows {
		marker, marked := readSDNMarker(row.Alias)
		if row.Zone != b.cfg.SDNZone || (marked && marker.pool != b.scopePool(s)) ||
			(!marked && strings.HasPrefix(row.Alias, "vws:")) {
			continue
		}
		id, err := ids.SDNVPC(row.Zone, row.VNet)
		if err != nil {
			continue
		}
		out = append(out, sdnVPC{row: row, marker: marker, vpc: resource.Vpc{
			ID: id, OwnerID: s.Account, Cidr: marker.cidr, State: resource.VpcAvailable,
		}})
	}
	return out, nil
}

func vpcAccepted(
	s backend.Scope, key string, action resource.Action, v resource.Vpc,
) (resource.Accepted[resource.Vpc], error) {
	hash := sha256.Sum256([]byte(key))
	id, err := (syncOperation{
		action: action, kind: resource.KindVpc,
		local: strings.TrimPrefix(v.ID.String(), "vpc-"), keyHash: [8]byte(hash[:8]),
	}).encode()
	now := time.Now()
	return resource.Accepted[resource.Vpc]{Items: []resource.Vpc{v}, Operation: resource.Operation{
		ID: id, Action: action, State: resource.OperationSucceeded, OwnerID: s.Account,
		Targets: []resource.Ref{v.ID.Ref()}, CreateTime: now, UpdateTime: now,
	}}, err
}

// CreateVpc recovers its deterministic VNet and alias after a lost response.
func (b *Backend) CreateVpc(
	ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	pool, err := b.poolForMutation(ctx, m.Scope)
	if b.cfg.ReadOnly || b.cfg.SDNZone == "" {
		return resource.Accepted[resource.Vpc]{}, resource.Unsupported("CreateVpc", "read-only or no sdn_zone configured")
	}
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	if len(req.Tags) != 0 {
		return resource.Accepted[resource.Vpc]{}, resource.Unsupported("CreateVpc", "TagSpecification is not supported")
	}
	p, err := netip.ParsePrefix(req.Cidr)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, resource.Invalid("cidrBlock", "invalid IPv4 CIDR")
	}
	if err := CheckVPCCIDR(p); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	if !launchHex(m.Key, 64) || !launchHex(m.Fingerprint, 64) {
		return resource.Accepted[resource.Vpc]{}, resource.Invalid("clientToken", "invalid mutation identity")
	}
	sum := sha256.Sum256([]byte(b.cluster + pool + m.Key))
	name := "v" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))[:7]
	marker := sdnMarker{cidr: req.Cidr, pool: pool, fp: m.Fingerprint[:16]}
	b.sdnMu.Lock()
	defer b.sdnMu.Unlock()
	rows, err := b.client.SDNVNets(ctx)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	exists := false
	for _, row := range rows {
		if row.VNet != name {
			continue
		}
		exists = true
		prior, marked := readSDNMarker(row.Alias)
		if !marked || prior.pool != pool || row.Zone != b.cfg.SDNZone || row.State == "deleted" {
			return resource.Accepted[resource.Vpc]{}, resource.Conflict(resource.KindVpc, name, "VNet name is occupied")
		}
		if prior != marker {
			return resource.Accepted[resource.Vpc]{}, resource.IdempotencyMismatch()
		}
	}
	if !exists {
		if err := b.client.CreateVNet(ctx, name, b.cfg.SDNZone, marker.alias()); err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
	}
	if err := b.client.ApplySDN(ctx); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	id, err := ids.SDNVPC(b.cfg.SDNZone, name)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	return vpcAccepted(m.Scope, m.Key, resource.ActionCreateVpc, resource.Vpc{
		ID: id, OwnerID: m.Account, Cidr: req.Cidr, State: resource.VpcAvailable,
	})
}

// DeleteVpc only removes a marked VNet owned by the caller's pool.
func (b *Backend) DeleteVpc(
	ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	_, err := b.poolForMutation(ctx, m.Scope)
	if b.cfg.ReadOnly || b.cfg.SDNZone == "" {
		return resource.Accepted[resource.Vpc]{}, resource.Unsupported("DeleteVpc", "read-only or no sdn_zone configured")
	}
	if err != nil {
		if resource.CodeOf(err) == resource.CodePermissionDenied {
			err = resource.NotFound(resource.KindVpc, req.ID.String())
		}
		return resource.Accepted[resource.Vpc]{}, err
	}
	b.sdnMu.Lock()
	defer b.sdnMu.Unlock()
	rows, err := b.sdnVPCs(ctx, m.Scope)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	for _, row := range rows {
		if row.vpc.ID != req.ID {
			continue
		}
		if row.marker.pool == "" {
			return resource.Accepted[resource.Vpc]{}, resource.DirectReadOnly()
		}
		if row.row.State != "deleted" {
			if err := b.client.DeleteVNet(ctx, row.row.VNet); err != nil {
				return resource.Accepted[resource.Vpc]{}, err
			}
		}
		if err := b.client.ApplySDN(ctx); err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		row.vpc.State = resource.VpcDeleting
		return vpcAccepted(m.Scope, m.Key, resource.ActionDeleteVpc, row.vpc)
	}
	return resource.Accepted[resource.Vpc]{}, resource.NotFound(resource.KindVpc, req.ID.String())
}
