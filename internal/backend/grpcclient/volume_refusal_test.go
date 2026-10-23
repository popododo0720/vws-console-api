package grpcclient_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

// refusingVolumes is vws-storage refusing every CreateVolume the way its
// admission does: gRPC InvalidArgument with ErrorInfo INVALID_SPEC.
type refusingVolumes struct {
	storagev1.UnimplementedVolumeServiceServer
	msg string
}

func (s refusingVolumes) CreateVolume(
	context.Context, *storagev1.CreateVolumeRequest,
) (*longrunningpb.Operation, error) {
	st, err := status.New(codes.InvalidArgument, s.msg).
		WithDetails(&errdetails.ErrorInfo{Reason: "INVALID_SPEC", Domain: "vws.dev"})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, s.msg)
	}
	return nil, st.Err()
}

// A vws-storage refusal reaches the EC2 caller over a real gRPC connection
// with the EC2 code: a type storage does not serve is UnknownVolumeType
// ("The specified volume type is unsupported"), and IOPS, throughput or a
// size outside the type's range is InvalidParameterValue (EC2 API Reference,
// Error codes; messages as vws-storage#124 words them).
func TestStorageVolumeRefusalOverGRPCHasTheEC2Code(t *testing.T) {
	const unmapped = "invalid argument: volume type %s is unsupported: " +
		"invalid: no StorageClass is mapped to volume type %s"
	for _, tc := range []struct {
		typ, msg, code string
	}{
		{"gp3", strings.ReplaceAll(unmapped, "%s", "gp3"), "UnknownVolumeType"},
		{"standard", strings.ReplaceAll(unmapped, "%s", "standard"), "UnknownVolumeType"},
		{"gp3", "invalid argument: volume type gp3 needs iops from 3000 to 80000", "InvalidParameterValue"},
		{"gp3", "invalid argument: volume type gp3 needs throughput from 125 to 2000 MiB/s", "InvalidParameterValue"},
		{"gp3", "invalid argument: volume type gp3 allows at most 0.25 MiB/s of throughput per iops; " +
			"3000 iops allow 750 MiB/s", "InvalidParameterValue"},
		{"gp2", "invalid argument: volume type gp2 takes no iops", "InvalidParameterValue"},
		{"standard", "invalid argument: volume type standard needs a size from 1 to 1024 GiB", "InvalidParameterValue"},
	} {
		h, cred, now := ec2OverGRPC(t, refusingVolumes{msg: tc.msg})
		form := url.Values{}
		form.Set("Action", "CreateVolume")
		form.Set("Version", ec2query.Version)
		form.Set("AvailabilityZone", "vws-1a")
		form.Set("Size", "1")
		form.Set("VolumeType", tc.typ)
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
			t.Errorf("%q: want %s, got %d %s", tc.msg, tc.code, res.Code, res.Body)
		}
	}
}

// ec2OverGRPC is the EC2 Query surface on the gRPC backend, whose storage
// endpoint is vols on a loopback listener.
func ec2OverGRPC(t *testing.T, vols storagev1.VolumeServiceServer) (http.Handler, sigv4.Credential, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	storagev1.RegisterVolumeServiceServer(srv, vols)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	addr := "passthrough:///" + lis.Addr().String()
	client, err := grpcclient.Dial(t.Context(), grpcclient.Addrs{Compute: addr, Storage: addr, Network: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	h := ec2query.New(ec2query.Config{
		Service:    cloud.New(cloud.Config{Backends: client.Set()}),
		Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account),
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2,
			Region:  resource.RegionName,
			Now:     func() time.Time { return now },
			Auth:    iam.Authenticator(iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)),
		}),
	})
	return h, cred, now
}
