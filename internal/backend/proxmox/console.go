package proxmox

import (
	"context"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// OpenConsole checks live pool membership before requesting a PVE ticket.
func (b *Backend) OpenConsole(
	ctx context.Context, scope backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	if b.cfg.ReadOnly {
		return resource.ConsoleSession{}, resource.Unsupported("OpenConsole", "read-only")
	}
	vm, err := b.vmForMutation(ctx, scope, id)
	if err != nil {
		return resource.ConsoleSession{}, err
	}
	if kind != resource.ConsoleVNC && kind != resource.ConsoleSerial {
		return resource.ConsoleSession{}, resource.Invalid("kind", "expected vnc or serial")
	}
	if vm.Status != "running" {
		return resource.ConsoleSession{}, &resource.Error{Code: resource.CodeConflict, Message: "instance is not running"}
	}
	dial, err := b.client.Console(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID}, kind == resource.ConsoleSerial)
	if err != nil {
		return resource.ConsoleSession{}, &resource.Error{Code: resource.CodeUnavailable, Message: "console unavailable"}
	}
	expires := time.Now().Add(5 * time.Minute)
	var mu sync.Mutex
	used := false
	return resource.ConsoleSession{
		Kind: kind, Expires: expires,
		Dial: func(ctx context.Context) (resource.ConsoleStream, error) {
			mu.Lock()
			valid := !used && time.Now().Before(expires)
			used = true
			mu.Unlock()
			if !valid {
				return nil, resource.Denied("console session expired or already used")
			}
			if _, err := b.vmForMutation(ctx, scope, id); err != nil {
				return nil, err
			}
			return dial(ctx)
		},
	}, nil
}
