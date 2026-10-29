package grpcclient

import (
	"context"
	"fmt"
	"testing"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Detach records and their reserved operation id labels are console-api
// bookkeeping: EC2 counts only user tags. With 62 to 64 compute labels in
// use and detaches still pending, every call EC2 accepts goes through. A
// pending record either carries its fingerprint binding (written since
// #362) or has no vws-dop- label at all (written before #362), which
// reserves one more label (#334).
func TestPendingDetachRecordsNeverRefuseAnEC2Call(t *testing.T) {
	calls := map[string]func(context.Context, computeClient, backend.Scope, labelBudgetWorld) error{
		"CreateTags up to 50 tags": func(ctx context.Context, c computeClient, s backend.Scope, w labelBudgetWorld) error {
			tags := map[string]string{}
			for i := w.tagCount; i < resource.MaxTags; i++ {
				tags[fmt.Sprintf("k%02d", i)] = "v"
			}
			tags["k00"] = "changed" // a 50-tag instance can still change a value
			_, err := c.CreateTags(ctx, backend.Mutation{Scope: s, Key: "k-call", Fingerprint: "fp-call"},
				resource.CreateTagsRequest{IDs: []resource.InstanceID{w.inst}, Tags: tags})
			return err
		},
		"StopInstances": func(ctx context.Context, c computeClient, s backend.Scope, w labelBudgetWorld) error {
			_, err := c.StopInstances(ctx, backend.Mutation{Scope: s, Key: "k-call", Fingerprint: "fp-call"},
				resource.StopInstancesRequest{IDs: []resource.InstanceID{w.inst}})
			return err
		},
		"StartInstances": func(ctx context.Context, c computeClient, s backend.Scope, w labelBudgetWorld) error {
			w.world.mu.Lock()
			w.world.inst[0].Spec.Power = computev1.InstancePower_INSTANCE_POWER_STOPPED
			w.world.inst[0].Status.Power = computev1.InstancePower_INSTANCE_POWER_STOPPED
			w.world.mu.Unlock()
			_, err := c.StartInstances(ctx, backend.Mutation{Scope: s, Key: "k-call", Fingerprint: "fp-call"},
				resource.StartInstancesRequest{IDs: []resource.InstanceID{w.inst}})
			return err
		},
		"AttachVolume": func(ctx context.Context, c computeClient, s backend.Scope, w labelBudgetWorld) error {
			_, err := c.AttachVolume(ctx, backend.Mutation{Scope: s, Key: "k-call", Fingerprint: "fp-call"},
				resource.AttachVolumeRequest{VolumeID: w.vols[0], InstanceID: w.inst, Device: "/dev/sdf"})
			return err
		},
	}
	for _, bound := range []bool{true, false} {
		for _, labels := range []int{62, 63, 64} {
			for name, call := range calls {
				t.Run(fmt.Sprintf("binding=%t/%d labels/%s", bound, labels, name), func(t *testing.T) {
					w := pendingDetachAtLabels(t, labels, bound)
					ctx := context.Background()
					if err := call(ctx, w.client, w.scope, w); err != nil {
						t.Fatalf("%s at %d labels next to pending detaches: %v, want success", name, labels, err)
					}
					after := w.world.labelsOf(w.name)
					if len(after) > labelMax {
						t.Fatalf("%d labels stored, compute holds %d", len(after), labelMax)
					}
					for _, vol := range []resource.VolumeID{w.vols[3], w.vols[4], w.vols[5]} {
						if _, ok := after[labelDetachPrefix+vol.String()]; !ok {
							t.Fatalf("the record of %s, within its window, was dropped", vol)
						}
					}
					if !bound {
						return
					}
					// The pending detach is still answered for its token (#352).
					m := backend.Mutation{Scope: w.scope, Key: "k-new", Fingerprint: "fp-new"}
					got, err := w.client.DetachVolume(ctx, m,
						resource.DetachVolumeRequest{VolumeID: w.vols[5], InstanceID: w.inst})
					if err != nil || got.Operation.ID.IsZero() {
						t.Fatalf("same-token retry of the pending detach: %+v, %v", got.Operation, err)
					}
					if _, ok := w.world.labelsOf(w.name)[labelDetachOpPrefix+w.vols[5].String()]; !ok {
						t.Fatal("the retry did not save the pending detach's operation id")
					}
				})
			}
		}
	}
}

type labelBudgetWorld struct {
	world    *detachWorld
	client   computeClient
	name     string
	vols     []resource.VolumeID
	inst     resource.InstanceID
	scope    backend.Scope
	tagCount int
}

// pendingDetachAtLabels is heldRecordsNextToTags plus one more detach whose
// operation id write fails, at the given compute label count. Without bound
// that detach has no vws-dop- label, as code before #362 left it, and one
// more user tag takes the label its binding held.
func pendingDetachAtLabels(t *testing.T, labels int, bound bool) labelBudgetWorld {
	t.Helper()
	tagCount := labels - 16 // heldRecordsNextToTags' 14 and the new record with its binding
	world, client, name, vols, inst, scope := heldRecordsNextToTags(t, tagCount)
	world.mu.Lock()
	world.failSameSpec = 1
	world.mu.Unlock()
	m := backend.Mutation{Scope: scope, Key: "k-new", Fingerprint: "fp-new"}
	if _, err := client.DetachVolume(context.Background(), m,
		resource.DetachVolumeRequest{VolumeID: vols[5], InstanceID: inst}); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach: %v", err)
	}
	if !bound {
		world.mu.Lock()
		delete(world.inst[0].Labels, labelDetachOpPrefix+vols[5].String())
		world.inst[0].Labels[fmt.Sprintf("k%02d", tagCount)] = "v"
		world.mu.Unlock()
		tagCount++
	}
	if n := len(world.labelsOf(name)); n != labels {
		t.Fatalf("%d labels before the call, want %d", n, labels)
	}
	if tagCount > resource.MaxTags {
		t.Fatalf("%d tags: past EC2's limit", tagCount)
	}
	return labelBudgetWorld{world, client, name, vols, inst, scope, tagCount}
}
