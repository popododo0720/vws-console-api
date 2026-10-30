package grpcclient_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// growVolumes is vws-storage serving one volume of type typ at size GiB and
// counting the UpdateVolume calls it gets. vws-storage does not know the
// EBS size ranges, so the client must refuse before it calls.
type growVolumes struct {
	storagev1.UnimplementedVolumeServiceServer
	typ     storagev1.VolumeType
	size    int64
	updates *atomic.Int32
}

func (s growVolumes) GetVolume(_ context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	return &storagev1.Volume{
		Name: req.GetName(),
		Spec: &storagev1.VolumeSpec{SizeGib: s.size, Type: s.typ},
		Status: &storagev1.VolumeStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		},
	}, nil
}

func (s growVolumes) UpdateVolume(context.Context, *storagev1.UpdateVolumeRequest) (*longrunningpb.Operation, error) {
	s.updates.Add(1)
	return nil, status.Error(codes.Unavailable, "recorded")
}

// growStorage serves one volume of type typ at size GiB over gRPC and returns
// the client set plus the UpdateVolume call count.
func growStorage(t *testing.T, typ storagev1.VolumeType, size int64) (backend.Set, *atomic.Int32) {
	t.Helper()
	var updates atomic.Int32
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	storagev1.RegisterVolumeServiceServer(srv, growVolumes{typ: typ, size: size, updates: &updates})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	addr := "passthrough:///" + lis.Addr().String()
	client, err := grpcclient.Dial(t.Context(), grpcclient.Addrs{Compute: addr, Storage: addr, Network: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client.Set(), &updates
}

// #324 AC1: over gRPC, ModifyVolume past the type's EC2 maximum (ModifyVolume
// Size) is InvalidArgument (InvalidParameterValue on the wire) and never
// reaches vws-storage; a size in the range does reach it.
func TestModifyVolumeOverTypeMaximumNeverReachesStorage(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		typ      storagev1.VolumeType
		in, over int64
	}{
		{storagev1.VolumeType_VOLUME_TYPE_STANDARD, 1024, 1025},
		{storagev1.VolumeType_VOLUME_TYPE_GP2, 16384, 16385},
		{storagev1.VolumeType_VOLUME_TYPE_GP3, 65536, 65537},
		{storagev1.VolumeType_VOLUME_TYPE_ST1, 16384, 16385},
	} {
		set, updates := growStorage(t, tc.typ, 10)
		modify := func(size int64) error {
			m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-grow", Fingerprint: "fp-grow"}
			_, err := set.Compute.ModifyVolume(t.Context(), m, resource.ModifyVolumeRequest{ID: id, SizeGiB: size})
			return err
		}
		if err := modify(tc.over); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("%s to %d GiB: %v, want InvalidArgument", tc.typ, tc.over, err)
		}
		if n := updates.Load(); n != 0 {
			t.Errorf("%s to %d GiB: %d UpdateVolume calls, want 0", tc.typ, tc.over, n)
		}
		_ = modify(tc.in)
		if n := updates.Load(); n != 1 {
			t.Errorf("%s to %d GiB: %d UpdateVolume calls, want 1", tc.typ, tc.in, n)
		}
	}
}

// #436: a volume already above its type's maximum (a standard volume grown
// past 1,024 GiB before #427 capped each type) has no valid target: EC2
// requires the target at least the existing size and within the type's range,
// so a same-size or larger ModifyVolume is InvalidArgument and writes nothing.
func TestModifyVolumeAboveTypeMaximumNeverReachesStorage(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	set, updates := growStorage(t, storagev1.VolumeType_VOLUME_TYPE_STANDARD, 2048)
	for _, size := range []int64{2048, 4096} {
		m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-above-max", Fingerprint: "fp-above-max"}
		_, err := set.Compute.ModifyVolume(t.Context(), m, resource.ModifyVolumeRequest{ID: id, SizeGiB: size})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("to %d GiB: %v, want InvalidArgument", size, err)
		}
		if n := updates.Load(); n != 0 {
			t.Errorf("to %d GiB: %d UpdateVolume calls, want 0", size, n)
		}
	}
}
