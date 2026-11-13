package backendtest

import (
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// MutationWorld owns upstream state. Connect must construct a new backend over
// that state, without copying any process-local caches from a previous backend.
type MutationWorld struct {
	Connect   func() backend.Set
	Mutation  backend.Mutation
	OtherPool string
	Launch    resource.RunInstancesRequest
	Finalize  func() error
	// Interrupt stops execution at W2 (partial allocation), W3 (clones
	// allocated), or W4 (configured, before start). It returns the IDs already
	// allocated, so recovery cannot silently replace a partial launch.
	Interrupt func(window string) []resource.InstanceID
	// Denied returns a set using the real admission gate in the named state.
	Denied    func(state string) backend.Set
	Calls     func() int
	Writes    func() int
	CheckTask func(resource.OperationID, resource.InstanceID) error
}

// Phase2 selects mutation groups with supplied launch inputs instead of the
// full-feature groups, which require CreateSubnet and other optional actions.
// Each group gets an isolated upstream world; restarts within it share state.
func Phase2(world func(*testing.T) MutationWorld) Option {
	return func(o *options) { o.phase2 = world }
}

func runPhase2(t *testing.T, world func(*testing.T) MutationWorld, caps resource.RegionCapabilities) {
	t.Helper()
	t.Run("Phase2", func(t *testing.T) {
		for _, group := range []struct {
			name string
			run  func(*testing.T, MutationWorld)
		}{
			{"RestartIdempotency", restartIdempotency},
			{"PoolTenancy", poolTenancy},
			{"NotLeader", func(t *testing.T, w MutationWorld) { admissionRefusal(t, w, "leader") }},
			{"NoQuorum", func(t *testing.T, w MutationWorld) { admissionRefusal(t, w, "quorum") }},
			{"UPIDOperation", taskRoundTrip},
			{"Mutations", phase2Mutations},
			{"StorageMutations", phase2Storage},
		} {
			t.Run(group.name, func(t *testing.T) {
				requireCapabilities(t, caps, []resource.Action{
					resource.ActionRunInstances, resource.ActionCreateTags, resource.ActionStopInstances,
				}, nil)
				group.run(t, world(t))
			})
		}
		t.Run("LaunchCrashWindows", func(t *testing.T) {
			for _, window := range []string{"W2", "W3", "W4"} {
				t.Run(window, func(t *testing.T) {
					w := world(t)
					allocated := w.Interrupt(window)
					if len(allocated) == 0 || (window == "W2" && len(allocated) >= w.Launch.Count) {
						t.Fatalf("%s did not interrupt the expected allocation: %v", window, allocated)
					}
					set := w.Connect()
					accepted := phase2Launch(t, w, set)
					for _, id := range allocated {
						found := false
						for _, item := range accepted.Items {
							found = found || item.ID == id
						}
						if !found {
							t.Fatalf("%s replaced allocated instance %s", window, id)
						}
					}
					if err := w.Finalize(); err != nil {
						t.Fatal(err)
					}
					assertPhase2Launch(t, w, accepted)
					before := w.Writes()
					replayed := phase2Launch(t, w, w.Connect())
					if !reflect.DeepEqual(replayed.Items, accepted.Items) || w.Writes() != before {
						t.Fatal("completed launch replay wrote or changed its result")
					}
				})
			}
		})
	})
}

func phase2Launch(t *testing.T, w MutationWorld, set backend.Set) resource.Accepted[resource.Instance] {
	t.Helper()
	got, err := set.Compute.RunInstances(t.Context(), w.Mutation, w.Launch)
	if err != nil || len(got.Items) != w.Launch.Count || got.Operation.ID.IsZero() {
		t.Fatalf("launch: %+v, %v", got, err)
	}
	return got
}

func assertPhase2Launch(t *testing.T, w MutationWorld, accepted resource.Accepted[resource.Instance]) {
	t.Helper()
	set := w.Connect()
	op, err := set.Compute.GetOperation(t.Context(), w.Mutation.Scope, accepted.Operation.ID)
	if err != nil || op.ID != accepted.Operation.ID || op.State != resource.OperationSucceeded {
		t.Fatalf("recovered launch operation: %+v, %v", op, err)
	}
	page, err := set.Compute.DescribeInstances(t.Context(), w.Mutation.Scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != len(accepted.Items) {
		t.Fatalf("recovered inventory: %+v, %v", page, err)
	}
	for _, item := range accepted.Items {
		found := false
		for _, got := range page.Items {
			found = found || (got.ID == item.ID && got.State == resource.InstanceRunning)
		}
		if !found {
			t.Fatalf("original instance %s is not running after restart", item.ID)
		}
	}
}

func restartIdempotency(t *testing.T, w MutationWorld) {
	t.Helper()
	first := phase2Launch(t, w, w.Connect())
	before := w.Writes()
	set := w.Connect()
	replayed := phase2Launch(t, w, set)
	if !reflect.DeepEqual(first, replayed) || w.Writes() != before {
		t.Fatal("restart changed the accepted launch or wrote PVE")
	}
	clash := w.Mutation
	clash.Fingerprint = strings.Repeat("0", 64)
	if clash.Fingerprint == w.Mutation.Fingerprint {
		clash.Fingerprint = strings.Repeat("1", 64)
	}
	_, err := set.Compute.RunInstances(t.Context(), clash, w.Launch)
	if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("changed fingerprint: %v", err)
	}
	if w.Writes() != before {
		t.Fatal("fingerprint mismatch wrote PVE")
	}
}

func poolTenancy(t *testing.T, w MutationWorld) {
	t.Helper()
	set := w.Connect()
	first := phase2Launch(t, w, set)
	if err := w.Finalize(); err != nil {
		t.Fatal(err)
	}
	foreign := w.Mutation
	// Keep the same account: the transported pool binding is the authority,
	// independently of account-based tenancy.
	foreign.Pool = w.OtherPool
	before := w.Writes()
	_, err := set.Compute.CreateTags(t.Context(), foreign, resource.CreateTagsRequest{
		IDs: []resource.InstanceID{first.Items[0].ID}, Tags: map[string]string{"foreign": "write"},
	})
	if resource.CodeOf(err) != resource.CodeNotFound || w.Writes() != before {
		t.Fatalf("foreign pool mutation: %v; writes %d -> %d", err, before, w.Writes())
	}
	page, err := set.Compute.DescribeInstances(t.Context(), foreign.Scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("foreign pool inventory: %+v, %v", page, err)
	}
}

func admissionRefusal(t *testing.T, w MutationWorld, state string) {
	t.Helper()
	first := phase2Launch(t, w, w.Connect())
	if err := w.Finalize(); err != nil {
		t.Fatal(err)
	}
	set := w.Denied(state)
	before := w.Calls()
	_, err := set.Compute.CreateTags(t.Context(), w.Mutation, resource.CreateTagsRequest{
		IDs: []resource.InstanceID{first.Items[0].ID}, Tags: map[string]string{"denied": "write"},
	})
	if resource.CodeOf(err) != resource.CodeUnavailable || w.Calls() != before {
		t.Fatalf("%s admission reached PVE or succeeded: %v; calls %d -> %d", state, err, before, w.Calls())
	}
}

func taskRoundTrip(t *testing.T, w MutationWorld) {
	t.Helper()
	first := phase2Launch(t, w, w.Connect())
	if err := w.Finalize(); err != nil {
		t.Fatal(err)
	}
	id := first.Items[0].ID
	got, err := w.Connect().Compute.StopInstances(t.Context(), w.Mutation,
		resource.StopInstancesRequest{IDs: []resource.InstanceID{id}, Force: true})
	if err != nil || len(got.Items) != 1 {
		t.Fatalf("stop: %+v, %v", got, err)
	}
	if err := w.CheckTask(got.Operation.ID, id); err != nil {
		t.Fatal(err)
	}
	op, err := w.Connect().Compute.GetOperation(t.Context(), w.Mutation.Scope, got.Operation.ID)
	if err != nil || op.ID != got.Operation.ID || op.State != resource.OperationSucceeded ||
		op.Action != resource.ActionStopInstances || op.OwnerID != w.Mutation.Account {
		t.Fatalf("task operation after restart: %+v, %v", op, err)
	}
}

func phase2Mutations(t *testing.T, w MutationWorld) {
	t.Helper()
	set := w.Connect()
	accepted := phase2Launch(t, w, set)
	if err := w.Finalize(); err != nil {
		t.Fatal(err)
	}
	id := accepted.Items[0].ID
	tags := map[string]string{"Name": "contract", "empty": ""}
	got, err := set.Compute.CreateTags(t.Context(), w.Mutation,
		resource.CreateTagsRequest{IDs: []resource.InstanceID{id}, Tags: tags})
	if err != nil || len(got.Items) != 1 {
		t.Fatalf("CreateTags: %+v, %v", got, err)
	}
	page, err := w.Connect().Compute.DescribeInstances(t.Context(), w.Mutation.Scope,
		resource.InstanceQuery{IDs: []resource.InstanceID{id}})
	if err != nil || len(page.Items) != 1 || !maps.Equal(page.Items[0].Tags, tags) {
		t.Fatalf("tags after restart: %+v, %v", page, err)
	}
	if _, err := set.Compute.DeleteTags(t.Context(), w.Mutation, resource.DeleteTagsRequest{
		IDs: []resource.InstanceID{id}, Tags: []resource.TagSelector{{Key: "empty"}},
	}); err != nil {
		t.Fatal(err)
	}
	page, err = w.Connect().Compute.DescribeInstances(t.Context(), w.Mutation.Scope,
		resource.InstanceQuery{IDs: []resource.InstanceID{id}})
	if err != nil || len(page.Items) != 1 || !maps.Equal(page.Items[0].Tags, map[string]string{"Name": "contract"}) {
		t.Fatalf("DeleteTags after restart: %+v, %v", page, err)
	}
	if _, err := set.Compute.RebootInstances(t.Context(), w.Mutation,
		resource.RebootInstancesRequest{IDs: []resource.InstanceID{id}}); err != nil {
		t.Fatal(err)
	}
	if got := instanceState(t.Context(), t, set, w.Mutation.Scope, id); got != resource.InstanceRunning {
		t.Fatalf("reboot state: %s", got)
	}
	if _, err := set.Compute.StopInstances(t.Context(), w.Mutation,
		resource.StopInstancesRequest{IDs: []resource.InstanceID{id}, Force: true}); err != nil {
		t.Fatal(err)
	}
	if got := instanceState(t.Context(), t, set, w.Mutation.Scope, id); got != resource.InstanceStopped {
		t.Fatalf("stop state: %s", got)
	}
	if _, err := set.Compute.StartInstances(t.Context(), w.Mutation,
		resource.StartInstancesRequest{IDs: []resource.InstanceID{id}}); err != nil {
		t.Fatal(err)
	}
	if got := instanceState(t.Context(), t, set, w.Mutation.Scope, id); got != resource.InstanceRunning {
		t.Fatalf("start state: %s", got)
	}
	if _, err := set.Compute.TerminateInstances(t.Context(), w.Mutation,
		resource.TerminateInstancesRequest{IDs: []resource.InstanceID{id}}); err != nil {
		t.Fatal(err)
	}
	page, err = set.Compute.DescribeInstances(t.Context(), w.Mutation.Scope,
		resource.InstanceQuery{IDs: []resource.InstanceID{id}})
	if err != nil && resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ID == id && item.State != resource.InstanceTerminated {
			t.Fatalf("terminate state: %s", item.State)
		}
	}
}

func phase2Storage(t *testing.T, w MutationWorld) {
	t.Helper()
	set := w.Connect()
	launch := phase2Launch(t, w, set)
	if err := w.Finalize(); err != nil {
		t.Fatal(err)
	}
	id := launch.Items[0].ID
	m := w.Mutation
	m.Key = "storage-contract"
	tags := map[string]string{"Name": "data"}
	created, err := set.Compute.CreateVolume(t.Context(), m,
		resource.CreateVolumeRequest{Type: resource.VolumeGP2, SizeGiB: 1, Tags: tags})
	if err != nil || len(created.Items) != 1 {
		t.Fatalf("CreateVolume: %+v, %v", created, err)
	}
	vid := created.Items[0].ID
	page, err := w.Connect().Compute.DescribeVolumes(t.Context(), m.Scope,
		resource.VolumeQuery{IDs: []resource.VolumeID{vid}})
	if err != nil || len(page.Items) != 1 || !maps.Equal(page.Items[0].Tags, tags) {
		t.Fatalf("volume after restart: %+v, %v", page, err)
	}
	if _, err := set.Compute.TagVolumes(t.Context(), m,
		resource.TagVolumesRequest{IDs: []resource.VolumeID{vid}, Tags: map[string]string{"empty": ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.UntagVolumes(t.Context(), m, resource.UntagVolumesRequest{
		IDs: []resource.VolumeID{vid}, Tags: []resource.TagSelector{{Key: "empty"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.AttachVolume(t.Context(), m,
		resource.AttachVolumeRequest{VolumeID: vid, InstanceID: id, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	page, err = w.Connect().Compute.DescribeVolumes(t.Context(), m.Scope,
		resource.VolumeQuery{IDs: []resource.VolumeID{vid}})
	if err != nil || len(page.Items) != 1 || page.Items[0].State != resource.VolumeInUse ||
		page.Items[0].InstanceID != id || !maps.Equal(page.Items[0].Tags, tags) {
		t.Fatalf("attachment and volume tags after restart: %+v, %v", page, err)
	}
	if _, err := set.Compute.StopInstances(t.Context(), m,
		resource.StopInstancesRequest{IDs: []resource.InstanceID{id}, Force: true}); err != nil {
		t.Fatal(err)
	}
	m.Key = "detach-contract"
	if _, err := set.Compute.DetachVolume(t.Context(), m,
		resource.DetachVolumeRequest{VolumeID: vid, InstanceID: id, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	page, err = w.Connect().Compute.DescribeVolumes(t.Context(), m.Scope,
		resource.VolumeQuery{IDs: []resource.VolumeID{vid}})
	if err != nil || len(page.Items) != 1 || page.Items[0].State != resource.VolumeAvailable ||
		!page.Items[0].InstanceID.IsZero() {
		t.Fatalf("detach after restart: %+v, %v", page, err)
	}
	if _, err := set.Compute.DeleteVolume(t.Context(), m, resource.DeleteVolumeRequest{ID: vid}); err != nil {
		t.Fatal(err)
	}
	volumes, err := set.Compute.DescribeVolumes(t.Context(), m.Scope, resource.VolumeQuery{})
	if err != nil || len(volumes.Items) == 0 {
		t.Fatalf("root volumes: %+v, %v", volumes, err)
	}
	m.Key = "snapshot-contract"
	snap, err := set.Compute.CreateSnapshot(t.Context(), m,
		resource.CreateSnapshotRequest{VolumeID: volumes.Items[0].ID, Description: "contract"})
	if err != nil || len(snap.Items) != 1 {
		t.Fatalf("CreateSnapshot: %+v, %v", snap, err)
	}
	op, err := w.Connect().Compute.GetOperation(t.Context(), m.Scope, snap.Operation.ID)
	if err != nil || op.State != resource.OperationSucceeded {
		t.Fatalf("snapshot operation after restart: %+v, %v", op, err)
	}
}
