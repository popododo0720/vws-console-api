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
)

// launchWorld is compute and storage for one launch over the regional
// subnet: it keeps the live volumes, instances and private IPs, replays a
// request id the way the services do and fails the calls a test names.
type launchWorld struct {
	*regionalImages

	mu sync.Mutex
	// volumes maps a live volume to the instance it boots, "" before one.
	volumes map[string]string
	// ips maps a live instance's private IP to the instance.
	ips     map[string]string
	replays map[string]*longrunningpb.Operation
	calls   map[string]int
	faults  map[string]fault
	made    map[string]int
}

// fault fails times calls of a method from call number n, counted from 1.
// A lost fault makes the change and then fails, a response lost on the way
// back.
type fault struct {
	n, times int
	lost     bool
}

func (w *launchWorld) failAt(method string, n int, lost bool) {
	w.fail(method, fault{n: n, times: 1, lost: lost})
}

func (w *launchWorld) fail(method string, f fault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.faults[method] = f
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
	before, after := w.enter(method)
	if before {
		return nil, errDown()
	}
	if err := change(); err != nil {
		return nil, err
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
	before, _ := w.enter("GetInstance")
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

// startLaunchWorld serves a launchWorld and returns a client over it.
func startLaunchWorld(t *testing.T) (*launchWorld, computeClient) {
	t.Helper()
	w := &launchWorld{
		regionalImages: &regionalImages{},
		volumes:        map[string]string{}, ips: map[string]string{},
		replays: map[string]*longrunningpb.Operation{},
		calls:   map[string]int{}, faults: map[string]fault{}, made: map[string]int{},
	}
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, w)
	storagev1.RegisterVolumeServiceServer(srv, w)
	networkv1.RegisterVpcServiceServer(srv, w)
	networkv1.RegisterSubnetServiceServer(srv, w)
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
	return w, computeClient{&api{
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
		subnets:   networkv1.NewSubnetServiceClient(conn),
		vpcs:      networkv1.NewVpcServiceClient(conn),
	}}
}
