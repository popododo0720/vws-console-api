package grpcclient

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// launchWorld is compute, storage and network for one launch: it keeps the
// live volumes, instances and private IPs, replays a request id the way the
// services do, deletes an instance's boot volume with it and refuses to
// delete an attached volume. A delete answers a pending operation that is
// done on the first poll.
type launchWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	longrunningpb.UnimplementedOperationsServer

	mu sync.Mutex
	// volumes maps a live volume to the instance it boots, "" before one.
	volumes map[string]string
	// instances maps a live instance to its private IP.
	instances map[string]string
	ips       map[string]string
	labels    map[string]map[string]string
	replays   map[string]*longrunningpb.Operation
	pending   map[string]*longrunningpb.Operation
	calls     map[string]int
	faults    map[string]fault
	nextIP    int
	// made counts the volumes and instances ever created.
	madeVolumes, madeInstances int
	deletes                    []string
}

// fault fails times calls of a method from call number n, counted from 1.
// A lost fault makes the change and then fails, a response lost on the way
// back.
type fault struct {
	n, times int
	lost     bool
}

func (w *launchWorld) failAt(method string, n int, lost bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults[method] = fault{n: n, times: 1, lost: lost}
}

func (w *launchWorld) failFor(method string, n, times int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults[method] = fault{n: n, times: times}
}

// enter counts a call of method and reports whether it fails before or after
// its change.
func (w *launchWorld) enter(method string) (before, after bool) {
	w.calls[method]++
	f, ok := w.faults[method]
	if call := w.calls[method]; !ok || call < f.n || call >= f.n+f.times {
		return false, false
	}
	return !f.lost, f.lost
}

func errDown() error { return status.Error(codes.Unavailable, "backend down") }

// left is what the launch left behind: live volumes, instances and IPs.
func (w *launchWorld) left() (volumes, instances, ips int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.volumes), len(w.instances), len(w.ips)
}

func (w *launchWorld) CreateVolume(
	_ context.Context, req *storagev1.CreateVolumeRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if op, ok := w.replays[req.GetRequestId()]; ok {
		return op, nil
	}
	before, after := w.enter("CreateVolume")
	if before {
		return nil, errDown()
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	name := volumeName(projectID, req.GetVolumeId())
	if _, ok := w.volumes[name]; ok {
		return nil, status.Error(codes.AlreadyExists, name)
	}
	w.volumes[name] = ""
	w.madeVolumes++
	op, err := doneNamed(name, commonv1.OperationVerb_OPERATION_VERB_CREATE)
	if err != nil {
		return nil, err
	}
	w.replays[req.GetRequestId()] = op
	if after {
		return nil, errDown()
	}
	return op, nil
}

func (w *launchWorld) CreateInstance(
	_ context.Context, req *computev1.CreateInstanceRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if op, ok := w.replays[req.GetRequestId()]; ok {
		return op, nil
	}
	before, after := w.enter("CreateInstance")
	if before {
		return nil, errDown()
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	name := instanceName(projectID, req.GetInstanceId())
	if _, ok := w.instances[name]; ok {
		return nil, status.Error(codes.AlreadyExists, name)
	}
	boot := req.GetInstance().GetSpec().GetVolumes()[0].GetVolume()
	if owner, ok := w.volumes[boot]; !ok || owner != "" {
		return nil, status.Error(codes.FailedPrecondition, "boot volume "+boot)
	}
	w.nextIP++
	ip := "10.0.0." + strconv.Itoa(w.nextIP)
	w.volumes[boot], w.instances[name], w.ips[ip] = name, ip, name
	w.madeInstances++
	w.labels[name] = req.GetInstance().GetLabels()
	op, err := doneNamed(name, commonv1.OperationVerb_OPERATION_VERB_CREATE)
	if err != nil {
		return nil, err
	}
	w.replays[req.GetRequestId()] = op
	if after {
		return nil, errDown()
	}
	return op, nil
}

func (w *launchWorld) GetInstance(_ context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if before, _ := w.enter("GetInstance"); before {
		return nil, errDown()
	}
	if _, ok := w.instances[req.GetName()]; !ok {
		return nil, status.Error(codes.NotFound, req.GetName())
	}
	return &computev1.Instance{
		Name:   req.GetName(),
		Labels: w.labels[req.GetName()],
		Spec: &computev1.InstanceSpec{
			MachineType: "vws.small",
			Power:       computev1.InstancePower_INSTANCE_POWER_RUNNING,
			NetworkInterfaces: []*computev1.NetworkInterface{{
				DeviceName: "nic0",
				Subnet:     "projects/a123456789012/regions/" + resource.RegionName + "/vpcs/vpc-01234567/subnets/subnet-01234567",
			}},
		},
		Status: &computev1.InstanceStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING},
			Power:    computev1.InstancePower_INSTANCE_POWER_RUNNING,
		},
	}, nil
}

func (w *launchWorld) DeleteInstance(
	_ context.Context, req *computev1.DeleteInstanceRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if before, _ := w.enter("DeleteInstance"); before {
		return nil, errDown()
	}
	name := req.GetName()
	ip, ok := w.instances[name]
	if !ok {
		return nil, status.Error(codes.NotFound, name)
	}
	delete(w.instances, name)
	delete(w.ips, ip)
	for vol, owner := range w.volumes {
		if owner == name {
			delete(w.volumes, vol)
		}
	}
	w.deletes = append(w.deletes, name)
	return w.pend(name), nil
}

func (w *launchWorld) DeleteVolume(
	_ context.Context, req *storagev1.DeleteVolumeRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if before, _ := w.enter("DeleteVolume"); before {
		return nil, errDown()
	}
	name := req.GetName()
	owner, ok := w.volumes[name]
	if !ok {
		return nil, status.Error(codes.NotFound, name)
	}
	if owner != "" {
		return nil, status.Error(codes.FailedPrecondition, name+" is attached to "+owner)
	}
	delete(w.volumes, name)
	w.deletes = append(w.deletes, name)
	return w.pend(name), nil
}

func (w *launchWorld) pend(name string) *longrunningpb.Operation {
	op := &longrunningpb.Operation{Name: "operations/delete-" + strconv.Itoa(len(w.pending))}
	w.pending[op.GetName()] = op
	return op
}

func (w *launchWorld) GetOperation(
	_ context.Context, req *longrunningpb.GetOperationRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	op, ok := w.pending[req.GetName()]
	if !ok {
		return nil, status.Error(codes.NotFound, req.GetName())
	}
	return &longrunningpb.Operation{Name: op.GetName(), Done: true}, nil
}

func (w *launchWorld) ListVpcs(_ context.Context, req *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return &networkv1.ListVpcsResponse{Vpcs: []*networkv1.Vpc{{Name: vpcName(projectID, "vpc-01234567")}}}, nil
}

func (w *launchWorld) ListSubnets(
	_ context.Context, req *networkv1.ListSubnetsRequest,
) (*networkv1.ListSubnetsResponse, error) {
	return &networkv1.ListSubnetsResponse{Subnets: []*networkv1.Subnet{{
		Name: req.GetParent() + "/subnets/subnet-01234567",
	}}}, nil
}

// startLaunchWorld serves a launchWorld and returns a client over it.
func startLaunchWorld(t *testing.T) (*launchWorld, computeClient) {
	t.Helper()
	w := &launchWorld{
		volumes: map[string]string{}, instances: map[string]string{}, ips: map[string]string{},
		labels:  map[string]map[string]string{},
		replays: map[string]*longrunningpb.Operation{}, pending: map[string]*longrunningpb.Operation{},
		calls: map[string]int{}, faults: map[string]fault{},
	}
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, w)
	storagev1.RegisterVolumeServiceServer(srv, w)
	networkv1.RegisterVpcServiceServer(srv, w)
	networkv1.RegisterSubnetServiceServer(srv, w)
	longrunningpb.RegisterOperationsServer(srv, w)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///launch",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ops := longrunningpb.NewOperationsClient(conn)
	return w, computeClient{&api{
		instances:  computev1.NewInstanceServiceClient(conn),
		volumes:    storagev1.NewVolumeServiceClient(conn),
		subnets:    networkv1.NewSubnetServiceClient(conn),
		vpcs:       networkv1.NewVpcServiceClient(conn),
		computeOps: ops,
		storageOps: ops,
	}}
}
