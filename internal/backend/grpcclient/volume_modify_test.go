package grpcclient_test

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
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

// modifyVolumes is vws-storage serving one 100 GiB gp3 volume at 4,000 IOPS
// and 250 MiB/s. It records each UpdateVolume and answers it with refusal.
type modifyVolumes struct {
	storagev1.UnimplementedVolumeServiceServer
	refusal error
	mu      *sync.Mutex
	got     *[]*storagev1.UpdateVolumeRequest
}

func (s modifyVolumes) GetVolume(_ context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	return &storagev1.Volume{
		Name: req.GetName(),
		Spec: &storagev1.VolumeSpec{
			SizeGib: 100, Type: storagev1.VolumeType_VOLUME_TYPE_GP3, Iops: 4000, ThroughputMibps: 250,
		},
		Status: &storagev1.VolumeStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		},
	}, nil
}

func (s modifyVolumes) UpdateVolume(
	_ context.Context,
	req *storagev1.UpdateVolumeRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.got = append(*s.got, req)
	return nil, s.refusal
}

func modifyStorage(t *testing.T, refusal error) (backend.Set, func() []*storagev1.UpdateVolumeRequest) {
	t.Helper()
	var (
		mu  sync.Mutex
		got []*storagev1.UpdateVolumeRequest
	)
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	storagev1.RegisterVolumeServiceServer(srv, modifyVolumes{refusal: refusal, mu: &mu, got: &got})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	addr := "passthrough:///" + lis.Addr().String()
	client, err := grpcclient.Dial(t.Context(), grpcclient.Addrs{Compute: addr, Storage: addr, Network: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client.Set(), func() []*storagev1.UpdateVolumeRequest {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

// #324 AC1: one ModifyVolume is one UpdateVolume whose mask names exactly
// the fields the request sets (vws-storage#87), with the target values
// Volume.Modify computed, so storage fills the same EC2 type-change defaults.
func TestModifyVolumeSendsOneMaskWithTheNamedFields(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		req  resource.ModifyVolumeRequest
		mask []string
		spec *storagev1.VolumeSpec
	}{
		{
			resource.ModifyVolumeRequest{SizeGiB: 200},
			[]string{"spec.size_gib"},
			&storagev1.VolumeSpec{SizeGib: 200, Type: storagev1.VolumeType_VOLUME_TYPE_GP3, Iops: 4000, ThroughputMibps: 250},
		},
		{
			resource.ModifyVolumeRequest{Type: resource.VolumeIO2},
			[]string{"spec.type"},
			&storagev1.VolumeSpec{SizeGib: 100, Type: storagev1.VolumeType_VOLUME_TYPE_IO2, Iops: 3000},
		},
		{
			resource.ModifyVolumeRequest{Iops: 8000, Throughput: 1000},
			[]string{"spec.iops", "spec.throughput_mibps"},
			&storagev1.VolumeSpec{SizeGib: 100, Type: storagev1.VolumeType_VOLUME_TYPE_GP3, Iops: 8000, ThroughputMibps: 1000},
		},
		{
			resource.ModifyVolumeRequest{SizeGiB: 500, Type: resource.VolumeIO1, Iops: 20000},
			[]string{"spec.size_gib", "spec.type", "spec.iops"},
			&storagev1.VolumeSpec{SizeGib: 500, Type: storagev1.VolumeType_VOLUME_TYPE_IO1, Iops: 20000},
		},
	} {
		set, got := modifyStorage(t, status.Error(codes.Unavailable, "recorded"))
		tc.req.ID = id
		m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-modify", Fingerprint: "fp-modify"}
		_, _ = set.Compute.ModifyVolume(t.Context(), m, tc.req)
		calls := got()
		if len(calls) != 1 {
			t.Fatalf("%+v: %d UpdateVolume calls, want 1", tc.req, len(calls))
		}
		spec := calls[0].GetVolume().GetSpec()
		if paths := calls[0].GetUpdateMask().GetPaths(); !slices.Equal(paths, tc.mask) {
			t.Errorf("%+v: mask %v, want %v", tc.req, paths, tc.mask)
		}
		if spec.GetSizeGib() != tc.spec.GetSizeGib() || spec.GetType() != tc.spec.GetType() ||
			spec.GetIops() != tc.spec.GetIops() || spec.GetThroughputMibps() != tc.spec.GetThroughputMibps() {
			t.Errorf("%+v: spec %v, want %v", tc.req, spec, tc.spec)
		}
	}
}

// #324 AC1: vws-storage refusing a target type it has no storage for is
// UnknownVolumeType on ModifyVolume as on CreateVolume (#335 r2).
func TestModifyVolumeToAnUnservedTypeIsUnknownVolumeType(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	set, _ := modifyStorage(
		t,
		status.Error(
			codes.InvalidArgument,
			"invalid argument: volume type sc1 is unsupported: invalid: no StorageClass is mapped to volume type sc1",
		),
	)
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-modify", Fingerprint: "fp-modify"}
	_, err = set.Compute.ModifyVolume(
		t.Context(),
		m,
		resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeSC1, SizeGiB: 125},
	)
	var e *resource.Error
	if !errors.As(err, &e) || e.Code != resource.CodeInvalidArgument || e.Field != "volumeType" {
		t.Fatalf("modify to an unserved type: %v, want InvalidArgument volumeType", err)
	}
}
