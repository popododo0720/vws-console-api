package iamclient

import (
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// awsStatus is a vws-iam status carrying an AWS code in ErrorInfo metadata.
func awsStatus(t *testing.T, code codes.Code, aws, msg string) *status.Status {
	t.Helper()
	st, err := status.New(code, msg).WithDetails(&errdetails.ErrorInfo{Metadata: map[string]string{"aws_code": aws}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The delete names the device read by its exact serial number and carries
// that read's etag and a UUID request_id, so vws-iam refuses a device that
// changed since and replays a retry.
func TestDeleteVirtualMFADeviceOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getMfaRes = &iamv1.MfaDevice{
		Name: "projects/123456789012/mfaDevices/alice-phone", Etag: "etag-1",
		Status: &iamv1.MfaDeviceStatus{SerialNumber: mfaSerial},
	}
	if err := admin.DeleteVirtualMFADevice(t.Context(), accountID(t), mfaSerial); err != nil {
		t.Fatal(err)
	}
	if len(s.deleteMfa) != 1 {
		t.Fatalf("sent %v", s.deleteMfa)
	}
	del := s.deleteMfa[0]
	if del.GetName() != "projects/123456789012/mfaDevices/alice-phone" || del.GetEtag() != "etag-1" ||
		!uuidV4.MatchString(del.GetRequestId()) || del.GetAllowMissing() {
		t.Errorf("delete request %v", del)
	}
}

// A lost response is retried with the same request_id, which vws-iam replays
// instead of deleting twice.
func TestDeleteVirtualMFADeviceRetryKeepsTheRequestID(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.deleteMfaFailFirst = 1
	if err := admin.DeleteVirtualMFADevice(t.Context(), accountID(t), mfaSerial); err != nil {
		t.Fatal(err)
	}
	if len(s.deleteMfa) != 2 || s.deleteMfa[0].GetRequestId() != s.deleteMfa[1].GetRequestId() {
		t.Fatalf("retry changed the request_id: %v", s.deleteMfa)
	}
}

func TestDeleteVirtualMFADeviceErrorsOverGRPC(t *testing.T) {
	notFound := func(t *testing.T, err error) {
		t.Helper()
		if resource.CodeOf(err) != resource.CodeNotFound || err.Error() != iam.MFADeviceNotFound().Error() {
			t.Fatalf("got %v, want NoSuchEntity", err)
		}
	}
	deleteConflict := func(t *testing.T, err error) {
		t.Helper()
		if resource.CodeOf(err) != resource.CodeConflict || iam.IsChanged(err) {
			t.Fatalf("got %v, want DeleteConflict", err)
		}
	}
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, s *server)
		serial  string
		check   func(t *testing.T, err error)
		deletes int
	}{
		{"missing device", func(_ *testing.T, s *server) {
			s.getMfaErr = status.Error(codes.NotFound, "no such device")
		}, mfaSerial, notFound, 0},
		{"same name on another path", func(_ *testing.T, s *server) {
			s.getMfaRes = &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: "arn:vws:iam::123456789012:mfa/eng/alice-phone",
			}}
		}, mfaSerial, notFound, 0},
		{"another account", func(*testing.T, *server) {}, mfaForeign, notFound, 0},
		{"enabled device", func(_ *testing.T, s *server) {
			s.getMfaRes = &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: mfaSerial, User: "projects/123456789012/users/alice",
			}}
		}, mfaSerial, deleteConflict, 0},
		{"enabled since the read", func(t *testing.T, s *server) {
			s.deleteMfaErr = awsStatus(t, codes.FailedPrecondition, "DeleteConflict", "mfa device is enabled for a user").Err()
		}, mfaSerial, deleteConflict, 1},
		{"etag race", func(t *testing.T, s *server) {
			s.deleteMfaErr = awsStatus(t, codes.Aborted, "ConcurrentModification", "etag does not match").Err()
		}, mfaSerial, func(t *testing.T, err error) {
			t.Helper()
			if !iam.IsChanged(err) {
				t.Fatalf("got %v, want ConcurrentModification", err)
			}
		}, 1},
		{"deleted since the read", func(_ *testing.T, s *server) {
			s.deleteMfaErr = status.Error(codes.NotFound, "gone")
		}, mfaSerial, notFound, 1},
		{"failed operation", func(t *testing.T, s *server) {
			st := awsStatus(t, codes.FailedPrecondition, "DeleteConflict", "mfa device is enabled for a user")
			s.deleteMfaRes = &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Error{Error: st.Proto()}}
		}, mfaSerial, deleteConflict, 1},
		{"running operation", func(_ *testing.T, s *server) {
			s.deleteMfaRes = &longrunningpb.Operation{Done: false}
		}, mfaSerial, func(t *testing.T, err error) {
			t.Helper()
			if resource.CodeOf(err) != resource.CodeInternal {
				t.Fatalf("got %v, want an internal fault", err)
			}
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			tc.setup(t, s)
			tc.check(t, STSAdmin{Client: c}.DeleteVirtualMFADevice(t.Context(), accountID(t), tc.serial))
			if len(s.deleteMfa) != tc.deletes {
				t.Fatalf("sent %d deletes, want %d: %v", len(s.deleteMfa), tc.deletes, s.deleteMfa)
			}
		})
	}
}
