package grpcclient

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"

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

// internalErrorMessage is the EC2 StateReason message for Server.InternalError.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StateReason.html
const internalErrorMessage = "Server.InternalError: " +
	"An internal error caused the instance to terminate during launch"

// errorWorld serves one healthy record beside a reconciliation ERROR record.
// DeleteInstance accepts the call and leaves the instance in place, which is
// the compute service before it can terminate from ERROR.
type errorWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	mu      sync.Mutex
	inst    []*computev1.Instance
	vol     []*storagev1.Volume
	deletes int
}

func (s *errorWorld) ListInstances(
	context.Context, *computev1.ListInstancesRequest,
) (*computev1.ListInstancesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &computev1.ListInstancesResponse{Instances: s.inst}, nil
}

func (s *errorWorld) GetInstance(_ context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() == req.GetName() {
			return inst, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing instance")
}

func (s *errorWorld) DeleteInstance(
	_ context.Context, req *computev1.DeleteInstanceRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	s.deletes++
	s.mu.Unlock()
	return doneNamed(req.GetName(), commonv1.OperationVerb_OPERATION_VERB_DELETE)
}

func (s *errorWorld) ListVolumes(
	context.Context, *storagev1.ListVolumesRequest,
) (*storagev1.ListVolumesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &storagev1.ListVolumesResponse{Volumes: s.vol}, nil
}

func (s *errorWorld) GetVolume(_ context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vol := range s.vol {
		if vol.GetName() == req.GetName() {
			return vol, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing volume")
}

func (s *errorWorld) deleteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletes
}

func dialErrorWorld(t *testing.T, world *errorWorld) computeClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, world)
	storagev1.RegisterVolumeServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///compute",
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

func observedInstance(
	projectID, id string, state commonv1.ReconciliationState, power computev1.InstancePower,
) *computev1.Instance {
	subnet := "projects/" + projectID + "/regions/" + resource.RegionName +
		"/vpcs/vpc-01234567/subnets/subnet-01234567"
	return &computev1.Instance{
		Name: instanceName(projectID, id),
		Labels: map[string]string{
			labelReservation: "r-01234567",
			labelImage:       "ami-0123456789abcdef0",
		},
		Spec: &computev1.InstanceSpec{
			MachineType: "vws.small",
			Power:       power,
			NetworkInterfaces: []*computev1.NetworkInterface{{
				DeviceName: "nic0",
				Subnet:     subnet,
			}},
		},
		Status: &computev1.InstanceStatus{
			Observed: &commonv1.ObservedState{State: state},
			Power:    power,
		},
	}
}

func observedVolume(projectID, id string, state commonv1.ReconciliationState, instance string) *storagev1.Volume {
	status := &storagev1.VolumeStatus{Observed: &commonv1.ObservedState{State: state}}
	if instance != "" {
		status.Instance = instanceName(projectID, instance)
	}
	return &storagev1.Volume{
		Name:   volumeName(projectID, id),
		Spec:   &storagev1.VolumeSpec{SizeGib: 8, Type: storagev1.VolumeType_VOLUME_TYPE_SSD},
		Status: status,
	}
}

func TestErrorRecordDoesNotFailDescribe(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const failedID = "i-0fedcba9876543210"
	const healthyID = "i-0123456789abcdef0"
	world := &errorWorld{
		inst: []*computev1.Instance{
			observedInstance(projectID, healthyID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
				computev1.InstancePower_INSTANCE_POWER_RUNNING),
			observedInstance(projectID, failedID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
				computev1.InstancePower_INSTANCE_POWER_UNSPECIFIED),
		},
		vol: []*storagev1.Volume{
			observedVolume(projectID, "vol-0123456789abcdef0",
				commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
			observedVolume(projectID, "vol-0fedcba9876543210",
				commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, ""),
			observedVolume(projectID, "vol-0abcdef0123456789",
				commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, failedID),
		},
	}
	client := dialErrorWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}

	page, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{})
	if err != nil {
		t.Fatalf("DescribeInstances: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("instances %d, want 2", len(page.Items))
	}
	byID := map[string]resource.Instance{}
	for _, inst := range page.Items {
		byID[inst.ID.String()] = inst
	}
	healthy := byID[healthyID]
	if healthy.State != resource.InstanceRunning || healthy.StateReason != (resource.StateReason{}) {
		t.Fatalf("healthy %+v", healthy)
	}
	failed := byID[failedID]
	if failed.State != resource.InstanceTerminated || failed.State.EC2Code() != 48 {
		t.Fatalf("failed state %s code %d", failed.State, failed.State.EC2Code())
	}
	if failed.StateReason.Code != "Server.InternalError" || failed.StateReason.Message != internalErrorMessage {
		t.Fatalf("reason %+v", failed.StateReason)
	}
	body, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = `"state":"terminated","stateReason":{"code":"Server.InternalError","message":"` +
		internalErrorMessage + `"}`
	if !strings.Contains(string(body), wantJSON) {
		t.Fatalf("console body %s", body)
	}
	healthyBody, err := json.Marshal(healthy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(healthyBody), "stateReason") {
		t.Fatalf("healthy console body %s", healthyBody)
	}

	one, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{failed.ID}})
	if err != nil || len(one.Items) != 1 || one.Items[0].State != resource.InstanceTerminated {
		t.Fatalf("describe one: %v %+v", err, one.Items)
	}

	volumes, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{})
	if err != nil {
		t.Fatalf("DescribeVolumes: %v", err)
	}
	if len(volumes.Items) != 3 {
		t.Fatalf("volumes %d, want 3", len(volumes.Items))
	}
	volByID := map[string]resource.Volume{}
	for _, vol := range volumes.Items {
		volByID[vol.ID.String()] = vol
	}
	if volByID["vol-0123456789abcdef0"].State != resource.VolumeAvailable {
		t.Fatalf("healthy volume %+v", volByID["vol-0123456789abcdef0"])
	}
	for _, id := range []string{"vol-0fedcba9876543210", "vol-0abcdef0123456789"} {
		if volByID[id].State != "error" {
			t.Fatalf("volume %s state %q", id, volByID[id].State)
		}
	}
	if volByID["vol-0abcdef0123456789"].InstanceID.String() != failedID {
		t.Fatalf("attached error volume %+v", volByID["vol-0abcdef0123456789"])
	}
}

func TestTerminateErrorInstanceIsIdempotent(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const failedID = "i-0fedcba9876543210"
	world := &errorWorld{
		inst: []*computev1.Instance{
			observedInstance(projectID, failedID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
				computev1.InstancePower_INSTANCE_POWER_UNSPECIFIED),
		},
	}
	client := dialErrorWorld(t, world)
	id, err := resource.Parse[resource.InstanceID](failedID)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"term-1", "term-2"} {
		acc, err := client.TerminateInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: account}, Key: key, Fingerprint: "fp",
		}, resource.TerminateInstancesRequest{IDs: []resource.InstanceID{id}})
		if err != nil {
			t.Fatalf("TerminateInstances %s: %v", key, err)
		}
		if len(acc.Items) != 1 || acc.Items[0].ID != id {
			t.Fatalf("items %+v", acc.Items)
		}
		if acc.Items[0].Previous != resource.InstanceTerminated ||
			acc.Items[0].Current != resource.InstanceTerminated {
			t.Fatalf("%s states %s -> %s", key, acc.Items[0].Previous, acc.Items[0].Current)
		}
	}
	if world.deleteCount() != 2 {
		t.Fatalf("DeleteInstance calls %d, want 2", world.deleteCount())
	}
}

// TestUnreadableReconcileIsAFailedRecord pins #191: a reconciliation state
// this process cannot read is a failed record, not a failed listing. Compute
// and storage emit UNSPECIFIED only for a lifecycle they do not know, so the
// record is listed the way ERROR is: a terminated instance with state reason
// Server.InternalError, and a volume in state error.
func TestUnreadableReconcileIsAFailedRecord(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const healthyID = "i-0123456789abcdef0"
	const brokenID = "i-0fedcba9876543210"
	for _, state := range []commonv1.ReconciliationState{
		commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED,
		99,
	} {
		world := &errorWorld{
			inst: []*computev1.Instance{
				observedInstance(projectID, healthyID,
					commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
					computev1.InstancePower_INSTANCE_POWER_RUNNING),
				observedInstance(projectID, brokenID, state,
					computev1.InstancePower_INSTANCE_POWER_RUNNING),
			},
			vol: []*storagev1.Volume{
				observedVolume(projectID, "vol-0123456789abcdef0",
					commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
				observedVolume(projectID, "vol-0fedcba9876543210", state, ""),
				observedVolume(projectID, "vol-0abcdef0123456789", state, brokenID),
			},
		}
		client := dialErrorWorld(t, world)
		ctx := context.Background()
		scope := backend.Scope{Account: account}

		page, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{})
		if err != nil {
			t.Fatalf("state %d: DescribeInstances: %v", state, err)
		}
		byID := map[string]resource.Instance{}
		for _, inst := range page.Items {
			byID[inst.ID.String()] = inst
		}
		if len(page.Items) != 2 || byID[healthyID].State != resource.InstanceRunning {
			t.Fatalf("state %d: instances %+v", state, page.Items)
		}
		broken := byID[brokenID]
		if broken.State != resource.InstanceTerminated || broken.StateReason.Code != "Server.InternalError" ||
			broken.StateReason.Message != internalErrorMessage {
			t.Fatalf("state %d: broken %s %+v", state, broken.State, broken.StateReason)
		}
		id, err := resource.Parse[resource.InstanceID](brokenID)
		if err != nil {
			t.Fatal(err)
		}
		one, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{id}})
		if err != nil || len(one.Items) != 1 || one.Items[0].State != resource.InstanceTerminated {
			t.Fatalf("state %d: describe one: %v %+v", state, err, one.Items)
		}

		volumes, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{})
		if err != nil {
			t.Fatalf("state %d: DescribeVolumes: %v", state, err)
		}
		volByID := map[string]resource.Volume{}
		for _, vol := range volumes.Items {
			volByID[vol.ID.String()] = vol
		}
		if len(volumes.Items) != 3 || volByID["vol-0123456789abcdef0"].State != resource.VolumeAvailable {
			t.Fatalf("state %d: volumes %+v", state, volumes.Items)
		}
		for _, vid := range []string{"vol-0fedcba9876543210", "vol-0abcdef0123456789"} {
			if volByID[vid].State != resource.VolumeError {
				t.Fatalf("state %d: volume %s state %q", state, vid, volByID[vid].State)
			}
		}
		vid, err := resource.Parse[resource.VolumeID]("vol-0fedcba9876543210")
		if err != nil {
			t.Fatal(err)
		}
		named, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{IDs: []resource.VolumeID{vid}})
		if err != nil || len(named.Items) != 1 || named.Items[0].State != resource.VolumeError {
			t.Fatalf("state %d: describe one volume: %v %+v", state, err, named.Items)
		}
	}
}

// TestOrphanBootVolumeFromRefusedLaunchIsListed pins the #197 record: the boot
// volume a refused RunInstances left before #199, failed by storage, with the
// image source and the instance label but no attachment. DescribeVolumes lists
// it in state error beside a healthy volume.
func TestOrphanBootVolumeFromRefusedLaunchIsListed(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	orphan := observedVolume(projectID, "vol-031ea7c88bfbff2cd",
		commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, "")
	orphan.Spec.Source = &storagev1.VolumeSpec_Image{Image: imageName(projectID, "ami-0b1900000000dead1")}
	orphan.Labels = map[string]string{labelInstance: "i-0fedcba9876543210"}
	world := &errorWorld{vol: []*storagev1.Volume{
		observedVolume(projectID, "vol-0123456789abcdef0",
			commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		orphan,
	}}
	client := dialErrorWorld(t, world)
	page, err := client.DescribeVolumes(context.Background(), backend.Scope{Account: account}, resource.VolumeQuery{})
	if err != nil {
		t.Fatalf("DescribeVolumes: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("volumes %+v", page.Items)
	}
	for _, vol := range page.Items {
		if vol.ID.String() == "vol-031ea7c88bfbff2cd" && vol.State != resource.VolumeError {
			t.Fatalf("orphan %+v", vol)
		}
	}
}
