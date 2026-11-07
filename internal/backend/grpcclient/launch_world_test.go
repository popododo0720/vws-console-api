package grpcclient

import (
	"context"
	"fmt"
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
)

// launchWorld is compute, storage and addresses for one launch over the
// regional subnet: it keeps the live volumes, instances, private IPs and
// Elastic IP associations, replays a request id the way the services do,
// deletes an instance's boot volume and IP with it, refuses to delete an
// attached volume, and refuses to delete an instance an address names
// (instance.proto). A delete answers a pending operation that is done on the
// first poll.
type launchWorld struct {
	*regionalImages
	longrunningpb.UnimplementedOperationsServer
	networkv1.UnimplementedAddressServiceServer

	mu sync.Mutex
	// volumes maps a live volume to the instance it boots, "" before one.
	volumes map[string]string
	// ips maps a live instance's private IP to the instance.
	ips map[string]string
	// addresses maps an address name to the instance it names, "" when free.
	addresses map[string]string
	replays   map[string]*longrunningpb.Operation
	pending   map[string]bool
	calls     map[string]int
	faults    map[string]fault
	made      map[string]int
	deletes   []string
	lis       *bufconn.Listener
}

// fault fails times calls of a method from call number n, counted from 1.
// A lost fault makes the change and then fails, a response lost on the way
// back. A crash fault is a lost one that also runs crash, the caller's
// process dying before it reads the answer.
type fault struct {
	n, times int
	lost     bool
	crash    func()
}

func (w *launchWorld) crashAt(method string, n int, crash func()) {
	w.fail(method, fault{n: n, times: 1, lost: true, crash: crash})
}

func (w *launchWorld) failAt(method string, n int, lost bool) {
	w.fail(method, fault{n: n, times: 1, lost: lost})
}

func (w *launchWorld) failFor(method string, n, times int) { w.fail(method, fault{n: n, times: times}) }

func (w *launchWorld) fail(method string, f fault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults[method] = f
}

// enter counts a call of method and reports whether it fails before or after
// its change, and the crash to run after it.
func (w *launchWorld) enter(method string) (before, after bool, crash func()) {
	w.calls[method]++
	f, ok := w.faults[method]
	if call := w.calls[method]; !ok || call < f.n || call >= f.n+f.times {
		return false, false, nil
	}
	return !f.lost, f.lost, f.crash
}

func errDown() error { return status.Error(codes.Unavailable, "backend down") }

// left is what the launch left behind: live volumes, instances and IPs.
func (w *launchWorld) left() (volumes, instances, ips int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, owner := range w.volumes {
		if owner != "" {
			instances++
		}
	}
	return len(w.volumes), instances, len(w.ips)
}

// create replays requestID, or makes name with change and remembers the
// operation under requestID.
func (w *launchWorld) create(method, requestID, name string, change func() error) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if op, ok := w.replays[requestID]; ok {
		return op, nil
	}
	before, after, crash := w.enter(method)
	if before {
		return nil, errDown()
	}
	if err := change(); err != nil {
		return nil, err
	}
	if crash != nil {
		crash()
	}
	w.made[method]++
	op, err := doneNamed(name, commonv1.OperationVerb_OPERATION_VERB_CREATE)
	if err != nil {
		return nil, err
	}
	w.replays[requestID] = op
	if after {
		return nil, errDown()
	}
	return op, nil
}

func (w *launchWorld) CreateVolume(
	_ context.Context, req *storagev1.CreateVolumeRequest,
) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	name := volumeName(projectID, req.GetVolumeId())
	return w.create("CreateVolume", req.GetRequestId(), name, func() error {
		if _, ok := w.volumes[name]; ok {
			return status.Error(codes.AlreadyExists, name)
		}
		w.volumes[name] = ""
		return nil
	})
}

func (w *launchWorld) CreateInstance(
	_ context.Context, req *computev1.CreateInstanceRequest,
) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	name := instanceName(projectID, req.GetInstanceId())
	boot := req.GetInstance().GetSpec().GetVolumes()[0].GetVolume()
	return w.create("CreateInstance", req.GetRequestId(), name, func() error {
		if owner, ok := w.volumes[boot]; !ok || owner != "" {
			return status.Error(codes.FailedPrecondition, "boot volume "+boot)
		}
		w.volumes[boot] = name
		w.ips["10.0.0."+strconv.Itoa(w.made["CreateInstance"]+1)] = name
		w.regionalImages.mu.Lock()
		w.labels = req.GetInstance().GetLabels()
		w.regionalImages.mu.Unlock()
		return nil
	})
}

// live reports whether an instance is live: its boot volume names it.
func (w *launchWorld) live(name string) bool {
	for _, owner := range w.volumes {
		if owner == name {
			return true
		}
	}
	return false
}

func (w *launchWorld) GetInstance(ctx context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	w.mu.Lock()
	before, _, _ := w.enter("GetInstance")
	live := w.live(req.GetName())
	w.mu.Unlock()
	if before {
		return nil, errDown()
	}
	if !live {
		return nil, status.Error(codes.NotFound, req.GetName())
	}
	return w.regionalImages.GetInstance(ctx, req)
}

// remove deletes name with change and answers a pending operation.
func (w *launchWorld) remove(method, name string, change func() error) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if before, _, _ := w.enter(method); before {
		return nil, errDown()
	}
	if err := change(); err != nil {
		return nil, err
	}
	op, err := doneNamed(name, commonv1.OperationVerb_OPERATION_VERB_DELETE)
	if err != nil {
		return nil, err
	}
	projectID, err := projectOfName(name)
	if err != nil {
		return nil, toStatus(err)
	}
	w.deletes = append(w.deletes, name)
	op.Name, op.Done = operationName(projectID, fmt.Sprintf("%016x", len(w.pending))), false
	w.pending[op.GetName()] = true
	return op, nil
}

func (w *launchWorld) DeleteInstance(
	_ context.Context, req *computev1.DeleteInstanceRequest,
) (*longrunningpb.Operation, error) {
	name := req.GetName()
	return w.remove("DeleteInstance", name, func() error {
		if !w.live(name) {
			return status.Error(codes.NotFound, name)
		}
		for addr, owner := range w.addresses {
			if owner == name {
				return status.Error(codes.FailedPrecondition, "DEPENDENCY_MISSING: "+addr+" names "+name)
			}
		}
		for vol, owner := range w.volumes {
			if owner == name {
				delete(w.volumes, vol)
			}
		}
		for ip, owner := range w.ips {
			if owner == name {
				delete(w.ips, ip)
			}
		}
		return nil
	})
}

func (w *launchWorld) DeleteVolume(
	_ context.Context, req *storagev1.DeleteVolumeRequest,
) (*longrunningpb.Operation, error) {
	name := req.GetName()
	return w.remove("DeleteVolume", name, func() error {
		owner, ok := w.volumes[name]
		switch {
		case !ok:
			return status.Error(codes.NotFound, name)
		case owner != "":
			return status.Error(codes.FailedPrecondition, name+" is attached to "+owner)
		}
		delete(w.volumes, name)
		return nil
	})
}

func (w *launchWorld) GetOperation(
	_ context.Context, req *longrunningpb.GetOperationRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pending[req.GetName()] {
		return nil, status.Error(codes.NotFound, req.GetName())
	}
	return &longrunningpb.Operation{Name: req.GetName(), Done: true}, nil
}

// startLaunchWorld serves a launchWorld and returns a client over it.
func startLaunchWorld(t *testing.T) (*launchWorld, computeClient) {
	t.Helper()
	w := &launchWorld{
		regionalImages: &regionalImages{},
		volumes:        map[string]string{}, ips: map[string]string{}, addresses: map[string]string{},
		replays: map[string]*longrunningpb.Operation{}, pending: map[string]bool{},
		calls: map[string]int{}, faults: map[string]fault{}, made: map[string]int{},
	}
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, w)
	storagev1.RegisterVolumeServiceServer(srv, w)
	networkv1.RegisterVpcServiceServer(srv, w)
	networkv1.RegisterSubnetServiceServer(srv, w)
	networkv1.RegisterAddressServiceServer(srv, w)
	longrunningpb.RegisterOperationsServer(srv, w)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	w.lis = lis
	client, _ := w.dial(t)
	return w, client
}

// dial returns a client over its own connection to w, one process's view.
func (w *launchWorld) dial(t *testing.T) (computeClient, *grpc.ClientConn) {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///launch",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return w.lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ops := longrunningpb.NewOperationsClient(conn)
	return computeClient{&api{
		instances:  computev1.NewInstanceServiceClient(conn),
		volumes:    storagev1.NewVolumeServiceClient(conn),
		subnets:    networkv1.NewSubnetServiceClient(conn),
		vpcs:       networkv1.NewVpcServiceClient(conn),
		addresses:  networkv1.NewAddressServiceClient(conn),
		computeOps: ops,
		storageOps: ops,
	}}, conn
}
