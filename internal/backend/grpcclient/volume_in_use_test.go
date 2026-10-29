package grpcclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

// refusingDeletes is vws-storage holding one gp3 volume and refusing every
// DeleteVolume with gRPC FailedPrecondition and the vws.dev reason given.
// deletes counts the DeleteVolume calls it answered.
type refusingDeletes struct {
	storagev1.UnimplementedVolumeServiceServer
	reason  string
	deletes *atomic.Int32
}

func (s refusingDeletes) GetVolume(
	_ context.Context, req *storagev1.GetVolumeRequest,
) (*storagev1.Volume, error) {
	return &storagev1.Volume{
		Name: req.GetName(),
		Spec: &storagev1.VolumeSpec{SizeGib: 8, Type: storagev1.VolumeType_VOLUME_TYPE_GP3},
		Status: &storagev1.VolumeStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		},
	}, nil
}

func (s refusingDeletes) DeleteVolume(
	_ context.Context, req *storagev1.DeleteVolumeRequest,
) (*longrunningpb.Operation, error) {
	s.deletes.Add(1)
	msg := "failed precondition: volume is attached to instance i-0123456789abcdef0"
	st, err := status.New(codes.FailedPrecondition, msg).
		WithDetails(&errdetails.ErrorInfo{Reason: s.reason, Domain: "vws.dev"})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, msg)
	}
	return nil, st.Err()
}

// #337 AC3: vws-storage refuses DeleteVolume on a volume an instance spec
// still uses with FailedPrecondition DEPENDENCY_MISSING (vws-storage#152).
// Over a real gRPC connection the EC2 caller gets VolumeInUse, as EC2
// answers DeleteVolume on an attached volume (EC2 API Reference, Error
// codes). Any other precondition refusal keeps the state error.
func TestDeleteAttachedVolumeOverGRPCIsVolumeInUse(t *testing.T) {
	const vol = "vol-0123456789abcdef0"
	for _, tc := range []struct {
		reason, code string
	}{
		{"DEPENDENCY_MISSING", "VolumeInUse"},
		{"DEPENDENCY_NOT_READY", "IncorrectState"},
	} {
		deletes := &atomic.Int32{}
		h, cred, now := ec2OverGRPC(t, refusingDeletes{reason: tc.reason, deletes: deletes})
		form := url.Values{}
		form.Set("Action", "DeleteVolume")
		form.Set("Version", ec2query.Version)
		form.Set("VolumeId", vol)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/",
			strings.NewReader(form.Encode()))
		req.Host = req.URL.Host
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "<Code>"+tc.code+"</Code>") {
			t.Errorf("%s: want 400 %s, got %d %s", tc.reason, tc.code, res.Code, res.Body)
		}
		if strings.Contains(res.Body.String(), "<return>true</return>") {
			t.Errorf("%s: delete reported success: %s", tc.reason, res.Body)
		}
		if got := deletes.Load(); got != 1 {
			t.Errorf("%s: storage saw %d DeleteVolume calls, want 1", tc.reason, got)
		}
	}
}
