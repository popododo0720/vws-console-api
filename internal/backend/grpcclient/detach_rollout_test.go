package grpcclient

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// During a rolling deploy (maxSurge 1) a replica built before #327 serves
// next to this one. It knows nothing of the label a pending detach reserves
// for its operation id: its label writes copy every vws-detach- and vws-dop-
// label over as stored, add the caller's tags, and stop only at compute's
// 64 labels (c09cba3 instanceUpdateLabels and withInternalLabels). The
// reservation is safe against it only because the detach's first write
// already stores that label (detachOpPending), so it is a real label every
// replica counts. This pins that: with the instance at 64 labels after the
// first write, the old replica's tag write between the detach's two writes
// is refused, and the detach saves its operation id in the label it holds
// and answers its retry (#332).
func TestAnOldReplicaCannotTakeAPendingOperationIDsLabel(t *testing.T) {
	world, client, name, vols, inst := capacityWorld(t, 1)
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	// Fill with tags EC2 accepts, three of them packed into vws-tags-
	// chunks, until the detach's record and its pending operation id take
	// the last two labels.
	tag := func(key string, tags map[string]string) {
		t.Helper()
		if _, err := client.CreateTags(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key},
			resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: tags}); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
	}
	long := strings.Repeat("x", 256)
	tag("k-long", map[string]string{"L0": long, "L1": long, "L2": long})
	plain := map[string]string{}
	for i := range labelMax - len(world.labelsOf(name)) - 2 {
		plain[fmt.Sprintf("k%02d", i)] = "v"
	}
	if len(plain)+3 > resource.MaxTags {
		t.Fatalf("%d tags: past EC2's limit", len(plain)+3)
	}
	tag("k-plain", plain)
	m := backend.Mutation{Scope: scope, Key: "k-detach", Fingerprint: "fp-detach"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	var once sync.Once
	var raced bool
	var afterFirst, oldWrite map[string]string
	var oldErr error
	world.mu.Lock()
	world.afterUpdate = func(up *computev1.UpdateInstanceRequest, err error) {
		if err != nil || up.GetRequestId() != requestUUID(m.Key, "detach") {
			return
		}
		once.Do(func() {
			raced = true
			got, err := world.GetInstance(ctx, &computev1.GetInstanceRequest{Name: name})
			if err != nil {
				oldErr = err
				return
			}
			afterFirst = maps.Clone(got.GetLabels())
			// The old replica's CreateTags: every stored label as it is,
			// one more tag, etag-checked.
			oldWrite = maps.Clone(got.GetLabels())
			oldWrite["k-old-replica"] = "v"
			_, oldErr = world.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
				RequestId:  "old-replica-create-tags",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
				Instance:   &computev1.Instance{Name: name, Etag: got.GetEtag(), Labels: oldWrite},
			})
		})
	}
	world.mu.Unlock()
	first, err := client.DetachVolume(ctx, m, req)
	if !raced {
		t.Fatal("the old replica's write did not run between the detach's writes")
	}
	// The detach is done in compute: it must be answered, not refused.
	if err != nil {
		t.Fatalf("detach after the old replica's write (%v): %v", oldErr, err)
	}
	pending, ok := afterFirst[labelDetachOpPrefix+vols[0].String()]
	if !ok || len(pending) < len(detachOpPending)+1 || pending[:len(detachOpPending)+1] != detachOpPending+" " {
		t.Fatalf("after the first write the operation id label is %q (present %v), want a stored %q binding",
			pending, ok, detachOpPending)
	}
	if n := len(afterFirst); n != labelMax {
		t.Fatalf("%d labels after the first write, want %d", n, labelMax)
	}
	// Without the stored binding this write would be 64 labels and take
	// the operation id's label; with it, it is 65 and compute refuses it,
	// as the old replica's own check does.
	if len(oldWrite) != labelMax+1 {
		t.Fatalf("setup: the old replica wrote %d labels, want %d", len(oldWrite), labelMax+1)
	}
	if status.Code(oldErr) != codes.InvalidArgument {
		t.Fatalf("the old replica's write of %d labels: %v, want refused", len(oldWrite), oldErr)
	}
	labels := world.labelsOf(name)
	if len(labels) != labelMax {
		t.Fatalf("%d labels, want %d", len(labels), labelMax)
	}
	if op := labels[labelDetachOpPrefix+vols[0].String()]; op == "" || op == pending {
		t.Fatalf("operation id label %q: not saved", op)
	}
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil || again.Operation.ID != first.Operation.ID {
		t.Fatalf("same-token retry: op %s, %v; want op %s", again.Operation.ID, err, first.Operation.ID)
	}
}
