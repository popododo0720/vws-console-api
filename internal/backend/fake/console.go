package fake

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// consoleSessionTTL is how long a session may wait to be opened: Proxmox
// gives a vncproxy or termproxy ticket five minutes.
const consoleSessionTTL = 5 * time.Minute

type console struct{ w *World }

func (c console) OpenConsole(
	ctx context.Context, s backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	if err := ctx.Err(); err != nil {
		return resource.ConsoleSession{}, err
	}
	if kind.String() == "" {
		return resource.ConsoleSession{}, resource.Invalid("kind", "must be vnc or serial")
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	now := c.w.now()
	c.w.settle(now)
	inst, ok := c.w.inst[id]
	if !ok || inst.OwnerID != s.Account {
		return resource.ConsoleSession{}, resource.NotFound(resource.KindInstance, id.String())
	}
	if inst.State != resource.InstanceRunning {
		return resource.ConsoleSession{}, resource.Conflict(
			resource.KindInstance, id.String(), "a console needs a running instance, not "+inst.State.String())
	}
	return resource.ConsoleSession{
		Kind:    kind,
		URL:     "wss://console.fake.invalid/instances/" + id.String() + "/" + kind.String(),
		Expires: now.Add(consoleSessionTTL),
	}, nil
}
