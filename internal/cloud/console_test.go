package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type consoleInventory struct {
	backend.Compute
	items []resource.Instance
	calls int
}

func (c *consoleInventory) DescribeInstances(
	_ context.Context, _ backend.Scope, _ resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	c.calls++
	return resource.Page[resource.Instance]{Items: c.items}, nil
}

type kernelConsole func(context.Context, backend.Scope, resource.InstanceID, resource.ConsoleKind) (
	resource.ConsoleSession, error,
)

func (f kernelConsole) OpenConsole(
	ctx context.Context, scope backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	return f(ctx, scope, id, kind)
}

func TestOpenConsoleKernelBoundaries(t *testing.T) {
	c := caller(t)
	id, _ := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	for _, tc := range []struct {
		name       string
		caller     resource.Caller
		id         resource.InstanceID
		kind       resource.ConsoleKind
		nilConsole bool
		caps       backend.Capabilities
		want       resource.Code
	}{
		{name: "missing caller", id: id, kind: resource.ConsoleVNC, want: resource.CodeUnauthenticated},
		{name: "missing id", caller: c, kind: resource.ConsoleVNC, want: resource.CodeInvalidArgument},
		{name: "unknown kind", caller: c, id: id, want: resource.CodeInvalidArgument},
		{
			name: "no console", caller: c, id: id, kind: resource.ConsoleVNC,
			nilConsole: true, want: resource.CodeInvalidArgument,
		},
		{
			name: "missing capability", caller: c, id: id, kind: resource.ConsoleVNC,
			caps: stubCapabilities{}, want: resource.CodeInvalidArgument,
		},
		{
			name: "unreadable capability", caller: c, id: id, kind: resource.ConsoleVNC,
			caps: stubCapabilities{err: errors.New("offline")}, want: resource.CodeInternal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := &consoleInventory{}
			set := backend.Set{Compute: inventory, Console: kernelConsole(func(
				context.Context, backend.Scope, resource.InstanceID, resource.ConsoleKind,
			) (resource.ConsoleSession, error) {
				t.Fatal("refused request reached console backend")
				return resource.ConsoleSession{}, nil
			})}
			if tc.nilConsole {
				set.Console = nil
			}
			s := New(Config{Backends: set, Capabilities: tc.caps})
			_, err := s.OpenConsole(t.Context(), tc.caller, tc.id, tc.kind)
			if resource.CodeOf(err) != tc.want || inventory.calls != 0 {
				t.Fatalf("refusal = %v; inventory calls = %d", err, inventory.calls)
			}
		})
	}
	for _, found := range []bool{false, true} {
		inventory := &consoleInventory{}
		if found {
			inventory.items = []resource.Instance{{ID: id, OwnerID: c.Account}}
		}
		opens := 0
		set := backend.Set{Compute: inventory, Console: kernelConsole(func(
			ctx context.Context, got backend.Scope, gotID resource.InstanceID, kind resource.ConsoleKind,
		) (resource.ConsoleSession, error) {
			opens++
			if _, ok := ctx.Deadline(); !ok || got.Account != c.Account ||
				got.Region != resource.RegionName || gotID != id || kind != resource.ConsoleSerial {
				t.Fatal("console scope, deadline or target changed")
			}
			return resource.ConsoleSession{}, nil
		})}
		_, err := New(Config{Backends: set}).OpenConsole(t.Context(), c, id, resource.ConsoleSerial)
		want, count := resource.CodeNotFound, 0
		if found {
			want, count = resource.CodeInvalidArgument, 1
			if !resource.IsUnsupported(resource.AsError(err)) {
				t.Fatalf("session without a dialer: %v", err)
			}
		}
		if resource.CodeOf(err) != want || opens != count || inventory.calls != 1 {
			t.Fatalf("found=%v: err=%v opens=%d reads=%d", found, err, opens, inventory.calls)
		}
	}
}
