package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// detachSpy records the mutation DetachVolume receives and stops there.
type detachSpy struct {
	backend.Compute
	seen []backend.Mutation
}

func (d *detachSpy) DetachVolume(
	_ context.Context, m backend.Mutation, _ resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	d.seen = append(d.seen, m)
	return resource.Accepted[resource.VolumeAttachment]{}, errors.New("stop")
}

// A detach without a client token gets a minted one that no caller can send
// again, so the backend is told not to remember it (#303).
func TestDetachVolumeMarksAMintedToken(t *testing.T) {
	spy := &detachSpy{}
	svc := New(Config{Backends: backend.Set{Compute: spy}})
	vol, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	req := resource.DetachVolumeRequest{VolumeID: vol}
	ctx := context.Background()
	_, _ = svc.DetachVolume(ctx, caller(t), resource.ClientToken{}, req)
	_, _ = svc.DetachVolume(ctx, caller(t), token(t, "detach-1"), req)
	if len(spy.seen) != 2 {
		t.Fatalf("backend saw %d detaches, want 2", len(spy.seen))
	}
	if !spy.seen[0].MintedToken {
		t.Error("a detach without a client token is not marked minted")
	}
	if spy.seen[1].MintedToken {
		t.Error("a detach with a client token is marked minted")
	}
}
