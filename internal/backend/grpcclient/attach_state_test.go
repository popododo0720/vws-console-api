package grpcclient

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestAttachLifecycleOverGRPC runs the #214 attach table over the resource
// API. Behind it the loopback storage names a volume's instance only once
// the attach settles, as vws-storage does once compute has put the disk on
// the VirtualMachine; until then only the instance spec holds the volume.
func TestAttachLifecycleOverGRPC(t *testing.T) {
	backendtest.AttachLifecycle(t, func() (backend.Set, func()) {
		start := time.Unix(1_700_000_000, 0).UTC()
		var offset atomic.Int64
		world := fake.New(fake.Options{
			Now:     func() time.Time { return start.Add(time.Duration(offset.Load())) },
			Latency: time.Second,
			Entropy: &fake.Sequence{},
		})
		set := dialLoopback(t, world, start)()
		return set, func() { offset.Add(int64(2 * time.Second)) }
	})
}

// specWorld serves instances whose specs name volumes, and volumes whose
// status may or may not name an instance, as vws-compute and vws-storage do
// between an accepted attach and the hot-plug.
type specWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	inst     []*computev1.Instance
	vol      []*storagev1.Volume
	listErr  error
	listings atomic.Int32
}

func (s *specWorld) ListInstances(
	context.Context, *computev1.ListInstancesRequest,
) (*computev1.ListInstancesResponse, error) {
	s.listings.Add(1)
	if s.listErr != nil {
		return nil, s.listErr
	}
	return &computev1.ListInstancesResponse{Instances: s.inst}, nil
}

func (s *specWorld) ListVolumes(
	context.Context, *storagev1.ListVolumesRequest,
) (*storagev1.ListVolumesResponse, error) {
	return &storagev1.ListVolumesResponse{Volumes: s.vol}, nil
}

func (s *specWorld) GetVolume(
	_ context.Context, req *storagev1.GetVolumeRequest,
) (*storagev1.Volume, error) {
	for _, vol := range s.vol {
		if vol.GetName() == req.GetName() {
			return vol, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing volume")
}

func dialSpecWorld(t *testing.T, world *specWorld) computeClient {
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
		log:       slog.New(slog.DiscardHandler),
	}}
}

// TestDescribeVolumesReadsPendingAttachFromSpec pins how a volume that
// storage does not report on an instance yet is shown (#214): the instance
// spec is the attachment.
func TestDescribeVolumesReadsPendingAttachFromSpec(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const instID = "i-0123456789abcdef0"
	const volID = "vol-0123456789abcdef0"
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	running := computev1.InstancePower_INSTANCE_POWER_RUNNING
	holder := func(state commonv1.ReconciliationState) *computev1.Instance {
		inst := observedInstance(projectID, instID, state, running)
		inst.Spec.Volumes = []*computev1.VolumeAttachment{
			{Volume: volumeName(projectID, "vol-0fedcba9876543210"), DeviceName: "/dev/xvda", Boot: true},
			{Volume: volumeName(projectID, volID), DeviceName: "/dev/sdf"},
		}
		return inst
	}
	badName := holder(ready)
	badName.Name = "projects/" + projectID + "/instances/i-0fedcba987654321f"
	// A record from another account's project must never become the
	// caller's attachment (AGENTS.md: a result naming another account is
	// rejected).
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	foreign := observedInstance(project(other), instID, ready, running)
	foreign.Spec.Volumes = holder(ready).GetSpec().GetVolumes()
	rows := []struct {
		name      string
		inst      []*computev1.Instance
		reported  string
		listErr   error
		wantState resource.VolumeState
		wantInst  string
		wantAtt   resource.AttachmentStatus
		wantCode  resource.Code
		wantLists int32
	}{
		{
			name: "a spec names it and storage does not", inst: []*computev1.Instance{holder(ready)},
			wantState: resource.VolumeInUse, wantInst: instID, wantAtt: resource.AttachmentAttaching, wantLists: 1,
		},
		{
			name: "storage names the instance", inst: []*computev1.Instance{holder(ready)}, reported: instID,
			wantState: resource.VolumeInUse, wantInst: instID, wantAtt: resource.AttachmentAttached,
		},
		{
			name: "no spec names it", inst: []*computev1.Instance{observedInstance(projectID, instID, ready, running)},
			wantState: resource.VolumeAvailable, wantLists: 1,
		},
		{
			name:      "only an instance compute failed names it",
			inst:      []*computev1.Instance{holder(commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR)},
			wantState: resource.VolumeAvailable, wantLists: 1,
		},
		{
			name: "a record with a bad name is skipped", inst: []*computev1.Instance{badName, holder(ready)},
			wantState: resource.VolumeInUse, wantInst: instID, wantAtt: resource.AttachmentAttaching, wantLists: 1,
		},
		{
			name: "compute cannot be read", inst: []*computev1.Instance{holder(ready)},
			listErr: status.Error(codes.Unavailable, "compute down"), wantCode: resource.CodeUnavailable, wantLists: 1,
		},
		{
			name: "compute does not answer in time", inst: []*computev1.Instance{holder(ready)},
			listErr:  status.Error(codes.DeadlineExceeded, "compute slow"),
			wantCode: resource.CodeUnavailable, wantLists: 1,
		},
		{
			name: "a foreign instance record is rejected", inst: []*computev1.Instance{foreign},
			wantCode: resource.CodeInternal, wantLists: 1,
		},
	}
	for _, row := range rows {
		for _, listed := range []bool{false, true} {
			name := row.name + ", by id"
			if listed {
				name = row.name + ", listed"
			}
			t.Run(name, func(t *testing.T) {
				world := &specWorld{
					inst:    row.inst,
					vol:     []*storagev1.Volume{observedVolume(projectID, volID, ready, row.reported)},
					listErr: row.listErr,
				}
				client := dialSpecWorld(t, world)
				q := resource.VolumeQuery{Page: resource.PageRequest{Size: 50}}
				if !listed {
					q.IDs = []resource.VolumeID{mustVolume(t, volID)}
				}
				page, err := client.DescribeVolumes(context.Background(), backend.Scope{Account: account}, q)
				if got := world.listings.Load(); got != row.wantLists {
					t.Fatalf("ListInstances calls %d, want %d", got, row.wantLists)
				}
				if row.wantCode != 0 {
					if resource.CodeOf(err) != row.wantCode {
						t.Fatalf("err %v, want code %v", err, row.wantCode)
					}
					return
				}
				if err != nil || len(page.Items) != 1 {
					t.Fatalf("describe: %v %+v", err, page.Items)
				}
				v := page.Items[0]
				if v.State != row.wantState || v.InstanceID.String() != row.wantInst || v.AttachState != row.wantAtt {
					t.Fatalf("got %s on %q %q, want %s on %q %q",
						v.State, v.InstanceID, v.AttachState, row.wantState, row.wantInst, row.wantAtt)
				}
				if row.wantAtt == resource.AttachmentAttaching && v.Device != "/dev/sdf" {
					t.Fatalf("device %q, want /dev/sdf from the spec", v.Device)
				}
			})
		}
	}
}

func mustVolume(t *testing.T, id string) resource.VolumeID {
	t.Helper()
	v, err := resource.Parse[resource.VolumeID](id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
