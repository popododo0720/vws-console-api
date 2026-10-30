package grpcclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRetryPastTheRequestIDWindowIsNotResent pins #305. A detach is applied
// but the write that saves its operation id fails, so its retry resends the
// original update by request id. compute remembers a request id for
// backend.ClientTokenWindow only. Past it the stub forgets every request id,
// and a resend would be a new update answered as the detach. The retry must
// answer IncorrectState without writing to compute; within the window it
// still returns the original detach.
func TestRetryPastTheRequestIDWindowIsNotResent(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name  string
		named bool
	}{
		{"instance named", true},
		{"volume only", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			world, client, name, vols, inst := capacityWorld(t, 1)
			now := start
			client.now = func() time.Time { return now }
			scope := backend.Scope{Account: mustAccount(t)}
			ctx := context.Background()
			m := backend.Mutation{Scope: scope, Key: "k-305", Fingerprint: "fp-305"}
			req := resource.DetachVolumeRequest{VolumeID: vols[0]}
			if tc.named {
				req.InstanceID = inst
			}
			world.mu.Lock()
			world.failSameSpec = 1 // the write that saves the operation id fails
			world.mu.Unlock()
			if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("interrupted detach: %v", err)
			}
			world.finishAll()
			setVolumeInstance(world, "", "")
			world.mu.Lock()
			original := world.byRequest[requestUUID(m.Key, "detach")]
			world.mu.Unlock()
			if original == nil {
				t.Fatal("no stored update for the detach")
			}
			want, err := operationFrom(original.op, resource.ServiceCompute)
			if err != nil {
				t.Fatal(err)
			}

			now = start.Add(backend.ClientTokenWindow - 2*backend.ClientTokenGrace)
			within, err := client.DetachVolume(ctx, m, req)
			if err != nil {
				t.Fatalf("retry within the window: %v", err)
			}
			if within.Operation.ID != want.ID {
				t.Fatalf("retry within the window gave op %s, want the detach %s", within.Operation.ID, want.ID)
			}

			// Undo the id the retry above saved: the record is again one
			// whose operation id was never saved.
			world.mu.Lock()
			for _, item := range world.inst {
				delete(item.Labels, labelDetachOpPrefix+vols[0].String())
			}
			world.byRequest = map[string]*detachRecord{}
			updates := world.updates
			world.mu.Unlock()

			for _, past := range []time.Duration{
				backend.ClientTokenWindow - backend.ClientTokenGrace,
				backend.ClientTokenWindow + time.Second,
			} {
				now = start.Add(past)
				_, err := client.DetachVolume(ctx, m, req)
				world.mu.Lock()
				wrote := world.updates - updates
				world.mu.Unlock()
				if wrote != 0 {
					t.Fatalf("retry %s after the detach wrote to compute %d times", past, wrote)
				}
				var rerr *resource.Error
				if !errors.As(err, &rerr) || rerr.Code != resource.CodeConflict ||
					rerr.Message != resource.VolumeNotInUse(vols[0]).Message {
					t.Fatalf("retry %s after the detach: %v, want IncorrectState %q",
						past, err, resource.VolumeNotInUse(vols[0]).Message)
				}
			}
			if vols := world.volumeNames(name); len(vols) != 1 {
				t.Fatalf("volumes after the retries: %v", vols)
			}
		})
	}
}
