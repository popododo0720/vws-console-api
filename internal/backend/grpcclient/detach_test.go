package grpcclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// detachWorld is a compute service that stores label replaces and completes
// an update immediately when the volume list does not change.
type detachWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	mu        sync.Mutex
	inst      []*computev1.Instance
	vol       *storagev1.Volume
	byRequest map[string]*longrunningpb.Operation
	updates   int
	nextOp    int
}

func (s *detachWorld) GetVolume(_ context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vol == nil || s.vol.GetName() != req.GetName() {
		return nil, status.Error(codes.NotFound, "missing volume")
	}
	return s.vol, nil
}

func (s *detachWorld) ListInstances(
	context.Context, *computev1.ListInstancesRequest,
) (*computev1.ListInstancesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &computev1.ListInstancesResponse{Instances: s.inst}, nil
}

func (s *detachWorld) GetInstance(_ context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() == req.GetName() {
			return inst, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing instance")
}

func (s *detachWorld) UpdateInstance(
	_ context.Context, req *computev1.UpdateInstanceRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op, ok := s.byRequest[req.GetRequestId()]; ok {
		return op, nil
	}
	var inst *computev1.Instance
	for _, item := range s.inst {
		if item.GetName() == req.GetInstance().GetName() {
			inst = item
			break
		}
	}
	if inst == nil {
		return nil, status.Error(codes.NotFound, "missing instance")
	}
	before := map[string]struct{}{}
	for _, v := range inst.GetSpec().GetVolumes() {
		before[v.GetVolume()] = struct{}{}
	}
	after := map[string]struct{}{}
	for _, v := range req.GetInstance().GetSpec().GetVolumes() {
		after[v.GetVolume()] = struct{}{}
	}
	changed := len(before) != len(after)
	if !changed {
		for name := range before {
			if _, ok := after[name]; !ok {
				changed = true
				break
			}
		}
	}
	inst.Labels = req.GetInstance().GetLabels()
	if inst.Spec == nil {
		inst.Spec = &computev1.InstanceSpec{}
	}
	inst.Spec.Volumes = req.GetInstance().GetSpec().GetVolumes()
	s.updates++
	s.nextOp++
	op, err := longOp(
		projectOfInstance(inst.GetName()), fmt.Sprintf("%016x", s.nextOp), inst.GetName(),
		req.GetRequestId(), commonv1.OperationVerb_OPERATION_VERB_UPDATE, time.Now().UTC(),
	)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !changed {
		op.Done = true
	}
	s.byRequest[req.GetRequestId()] = op
	return op, nil
}

func projectOfInstance(name string) string {
	projectID, err := projectOfName(name)
	if err != nil {
		return ""
	}
	return projectID
}

func dialDetachWorld(t *testing.T, world *detachWorld) computeClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, world)
	storagev1.RegisterVolumeServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///detach",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
	}}
}

func TestDetachKeepsLabelsAndReadsTheSpec(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID  = "i-0123456789abcdef0"
		otherID = "i-0fedcba9876543210"
		rootID  = "vol-0123456789abcdef0"
		dataID  = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Labels[labelLaunch] = "launch-1"
	holder.Labels["env"] = "dev"
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	other := observedInstance(projectID, otherID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	other.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0abcdef0123456789"), DeviceName: "boot", Boot: true},
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder, other},
		vol:       observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		byRequest: map[string]*longrunningpb.Operation{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := resource.Parse[resource.InstanceID](otherID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-wrong", Fingerprint: "fp-wrong",
	}, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: wrong, Device: "/dev/sdf",
	})
	if !resource.IsAttachmentNotFound(resource.AsError(err)) {
		t.Fatalf("wrong instance: %v", err)
	}
	if world.updateCount() != 0 {
		t.Fatalf("wrong instance wrote %d updates", world.updateCount())
	}

	mut := backend.Mutation{Scope: scope, Key: "k-detach", Fingerprint: "fp-detach"}
	detached, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatal(err)
	}
	item := detached.Items[0]
	if item.Status != resource.AttachmentDetaching || item.InstanceID != holderID || item.Device != "/dev/sdf" {
		t.Fatalf("detach %+v", item)
	}
	if detached.Operation.Action != resource.ActionDetachVolume {
		t.Fatalf("action %s", detached.Operation.Action)
	}
	assertDetachLabels(t, world.labelsOf(instanceName(projectID, instID)))
	vols := world.volumeNames(instanceName(projectID, instID))
	if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) {
		t.Fatalf("volumes after detach %v", vols)
	}

	replayed, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID, Device: "/dev/sdf",
	})
	if err != nil || replayed.Operation.ID != detached.Operation.ID {
		t.Fatalf("replay %v %+v", err, replayed)
	}
	if world.updateCount() != 1 {
		t.Fatalf("replay wrote a second update (%d)", world.updateCount())
	}

	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-again", Fingerprint: "fp-again",
	}, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID, Device: "/dev/sdf",
	})
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("second detach: %v", err)
	}
	assertDetachLabels(t, world.labelsOf(instanceName(projectID, instID)))
}

func (s *detachWorld) updateCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updates
}

func (s *detachWorld) labelsOf(name string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() == name {
			return inst.GetLabels()
		}
	}
	return nil
}

func (s *detachWorld) volumeNames(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() != name {
			continue
		}
		out := make([]string, 0, len(inst.GetSpec().GetVolumes()))
		for _, v := range inst.GetSpec().GetVolumes() {
			out = append(out, v.GetVolume())
		}
		return out
	}
	return nil
}

func assertDetachLabels(t *testing.T, labels map[string]string) {
	t.Helper()
	if labels[labelImage] != "ami-0123456789abcdef0" || labels[labelReservation] != "r-01234567" ||
		labels[labelLaunch] != "launch-1" || labels["env"] != "dev" {
		t.Fatalf("labels %+v", labels)
	}
}
