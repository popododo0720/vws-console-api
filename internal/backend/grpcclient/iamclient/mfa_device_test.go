package iamclient

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AWS GetMFADevice accepts only FIDO security key serial numbers, and vws-iam
// keeps no FIDO keys (popododo0720/vws-iam#133). Every serial number is
// NoSuchEntity, an enabled virtual mfa/ device included, and vws-iam's virtual
// device read is never called for this action.
func TestGetMFADeviceOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	// vws-iam holds an enabled virtual device for alice.
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
		Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/alice"},
	}}
	for _, tc := range []struct{ name, serial string }{
		{"a FIDO security key", "arn:vws:iam::123456789012:u2f/alice/testFidoKey-R1234"},
		{"an enabled virtual device", mfaSerial},
		{"a virtual device of another account", mfaForeign},
		{"a serial that is not an ARN", "not-an-arn"},
	} {
		dev, err := admin.GetMFADevice(t.Context(), accountID(t), tc.serial)
		if resource.CodeOf(err) != resource.CodeNotFound || err.Error() != iam.MFADeviceNotFound().Error() {
			t.Errorf("%s: %+v %v, want NoSuchEntity", tc.name, dev, err)
		}
	}
	// A failing vws-iam cannot change the answer, because it is not asked.
	s.getMfaErr = awsErr(codes.Unavailable, "UNAVAILABLE", "ServiceUnavailable")
	if _, err := admin.GetMFADevice(t.Context(), accountID(t), mfaSerial); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("with vws-iam unavailable: %v", err)
	}
	if len(s.getMfa) != 0 || len(s.getUser) != 0 {
		t.Fatalf("GetMFADevice read a virtual device: GetMfaDevice %v, GetUser %v", s.getMfa, s.getUser)
	}
}
