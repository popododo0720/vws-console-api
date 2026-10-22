package iamclient

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestGetMFADeviceOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getMfaRes = &iamv1.MfaDevice{
		Name: "projects/123456789012/mfaDevices/alice-phone",
		Status: &iamv1.MfaDeviceStatus{
			SerialNumber: mfaSerial,
			User:         "projects/123456789012/users/alice",
			EnableTime:   timestamppb.New(authTime),
		},
	}
	s.getUserRes = map[string]*iamv1.User{"projects/123456789012/users/alice": {
		Name:   "projects/123456789012/users/alice",
		Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/eng/alice"},
	}}
	dev, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial)
	if err != nil {
		t.Fatal(err)
	}
	if dev.UserName != "alice" || dev.UserARN != "arn:vws:iam::123456789012:user/eng/alice" ||
		dev.SerialNumber != mfaSerial || !dev.Enabled.Equal(authTime) {
		t.Fatalf("device %+v", dev)
	}
	if len(s.getMfa) != 1 || s.getMfa[0].GetName() != "projects/123456789012/mfaDevices/alice-phone" {
		t.Fatalf("looked up %v", s.getMfa)
	}
	if len(s.getUser) != 1 || s.getUser[0].GetName() != "projects/123456789012/users/alice" {
		t.Fatalf("read the owner %v", s.getUser)
	}
}

func TestGetMFADeviceUnassignedOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getMfaRes = &iamv1.MfaDevice{
		Name:   "projects/123456789012/mfaDevices/alice-phone",
		Status: &iamv1.MfaDeviceStatus{SerialNumber: mfaSerial},
	}
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("unassigned device mapped to %v", err)
	}
	if len(s.getUser) != 0 {
		t.Fatalf("looked up an owner of an unassigned device: %v", s.getUser)
	}
}

func TestGetMFADeviceErrorsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	ctx := t.Context()
	// A serial that names no device of the caller does not exist, as in AWS,
	// and never reaches vws-iam.
	for _, serial := range []string{"not-an-arn", mfaForeign, "arn:vws:iam::123456789012:policy/device"} {
		if _, err := admin.GetMFADevice(ctx, accountID(t), serial); resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("serial %q mapped to %v", serial, err)
		}
	}
	if len(s.getMfa) != 0 || len(s.getUser) != 0 {
		t.Fatalf("a malformed call reached vws-iam: %v %v", s.getMfa, s.getUser)
	}
	// vws-iam addresses the device by its resource name, so the stored serial
	// number must match the serial number the caller sent.
	s.getMfaRes = &iamv1.MfaDevice{
		Name: "projects/123456789012/mfaDevices/alice-phone",
		Status: &iamv1.MfaDeviceStatus{
			SerialNumber: mfaSerial,
			User:         "projects/123456789012/users/alice",
		},
	}
	for _, serial := range []string{
		"arn:aws:iam::123456789012:mfa/alice-phone",
		"arn:vws:iam:us-east-1:123456789012:mfa/alice-phone",
		"arn:vws:iam::123456789012:mfa/admin/alice-phone",
	} {
		if _, err := admin.GetMFADevice(ctx, accountID(t), serial); resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("serial %q mapped to %v", serial, err)
		}
	}
	if len(s.getUser) != 0 {
		t.Fatalf("a wrong-serial call read a user: %v", s.getUser)
	}
	// A vws-iam NotFound on the device lookup is the same NoSuchEntity answer.
	s.getMfaErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if _, err := admin.GetMFADevice(ctx, accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing device mapped to %v", err)
	}
}

func TestGetMFADeviceOwnerErrorsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getMfaRes = &iamv1.MfaDevice{
		Name: "projects/123456789012/mfaDevices/alice-phone",
		Status: &iamv1.MfaDeviceStatus{
			SerialNumber: mfaSerial,
			User:         "projects/123456789012/users/alice",
		},
	}
	// A user that no longer exists makes the device unreadable.
	s.getUserErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing owner mapped to %v", err)
	}
	// A user resource in another project is a backend fault and is never read.
	s.getUserErr = nil
	s.getMfaRes.Status.User = "projects/210987654321/users/alice"
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("foreign owner mapped to %v", err)
	}
	if len(s.getUser) != 1 {
		t.Fatalf("a foreign owner reached vws-iam: %v", s.getUser)
	}
	// An owner ARN in another account is a backend fault.
	s.getMfaRes.Status.User = "projects/123456789012/users/alice"
	s.getUserRes = map[string]*iamv1.User{"projects/123456789012/users/alice": {
		Name:   "projects/123456789012/users/alice",
		Status: &iamv1.UserStatus{Arn: "arn:vws:iam::210987654321:user/alice"},
	}}
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("foreign owner ARN mapped to %v", err)
	}
	if len(s.getUser) != 2 {
		t.Fatalf("owner reads %v", s.getUser)
	}
	// A user response without an ARN cannot authorize anything.
	s.getUserRes = map[string]*iamv1.User{"projects/123456789012/users/alice": {Name: "projects/123456789012/users/alice"}}
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("owner without an ARN mapped to %v", err)
	}
	if len(s.getUser) != 3 {
		t.Fatalf("owner reads %v", s.getUser)
	}
}
