package iamclient

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestListVirtualMFADevicesOverGRPC(t *testing.T) {
	c, s := harness(t)
	ctx := t.Context()
	const (
		assignedSerial   = "arn:vws:iam::123456789012:mfa/a-phone"
		unassignedSerial = "arn:vws:iam::123456789012:mfa/b-phone"
		lastSerial       = "arn:vws:iam::123456789012:mfa/c-phone"
		alice            = "projects/123456789012/users/alice"
	)
	enabled := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.listMfaDevicesPages = map[string]*iamv1.ListMfaDevicesResponse{
		"": {MfaDevices: []*iamv1.MfaDevice{
			{Status: &iamv1.MfaDeviceStatus{SerialNumber: unassignedSerial}},
			{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: assignedSerial, User: alice, EnableTime: timestamppb.New(enabled),
			}},
		}, NextPageToken: "next"},
		"next": {MfaDevices: []*iamv1.MfaDevice{
			{Status: &iamv1.MfaDeviceStatus{SerialNumber: lastSerial}},
		}},
	}
	s.getUserRes = map[string]*iamv1.User{alice: {
		Name: alice, Spec: &iamv1.UserSpec{Path: "/eng/"},
		Status:     &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/eng/alice", UniqueId: "AIDAALICE"},
		CreateTime: timestamppb.New(created),
	}}

	admin := STSAdmin{Client: c}
	page, err := admin.ListVirtualMFADevices(ctx, accountID(t), iam.MFADeviceAssignmentAny, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.listMfaDevices) != 2 {
		t.Fatalf("sent %v", s.listMfaDevices)
	}
	if got := s.listMfaDevices[0]; got.GetParent() != "projects/123456789012" ||
		got.GetPageSize() != iam.MaxMFADevicePageSize || got.GetPageToken() != "" {
		t.Errorf("first request %+v", got)
	}
	if got := s.listMfaDevices[1].GetPageToken(); got != "next" {
		t.Errorf("second page token %q", got)
	}
	if !page.IsTruncated || page.Marker != unassignedSerial || len(page.Devices) != 2 {
		t.Fatalf("page %+v", page)
	}
	if page.Devices[0].SerialNumber != assignedSerial || page.Devices[1].SerialNumber != unassignedSerial {
		t.Fatalf("serials %q %q", page.Devices[0].SerialNumber, page.Devices[1].SerialNumber)
	}
	user := page.Devices[0].User
	if user == nil || user.Name != "alice" || user.Path != "/eng/" || user.ID != "AIDAALICE" ||
		user.ARN != "arn:vws:iam::123456789012:user/eng/alice" || !user.Created.Equal(created) {
		t.Errorf("user %+v", user)
	}
	if !page.Devices[0].EnableDate.Equal(enabled) {
		t.Errorf("enable date %v", page.Devices[0].EnableDate)
	}
	if page.Devices[1].User != nil {
		t.Errorf("unassigned device has a user: %+v", page.Devices[1])
	}
	if len(s.getUser) != 1 || s.getUser[0].GetName() != alice {
		t.Errorf("user reads %v", s.getUser)
	}

	assigned, err := admin.ListVirtualMFADevices(ctx, accountID(t), iam.MFADeviceAssignmentAssigned, "", 0)
	if err != nil || len(assigned.Devices) != 1 || assigned.Devices[0].SerialNumber != assignedSerial {
		t.Fatalf("assigned page %+v, %v", assigned, err)
	}
	unassigned, err := admin.ListVirtualMFADevices(ctx, accountID(t), iam.MFADeviceAssignmentUnassigned, "", 0)
	if err != nil || len(unassigned.Devices) != 2 ||
		unassigned.Devices[0].SerialNumber != unassignedSerial || unassigned.Devices[1].SerialNumber != lastSerial {
		t.Fatalf("unassigned page %+v, %v", unassigned, err)
	}
	rest, err := admin.ListVirtualMFADevices(ctx, accountID(t), iam.MFADeviceAssignmentAny, unassignedSerial, 2)
	if err != nil || rest.IsTruncated || len(rest.Devices) != 1 || rest.Devices[0].SerialNumber != lastSerial {
		t.Fatalf("rest page %+v, %v", rest, err)
	}
}

func TestListVirtualMFADevicesErrorsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.listMfaDevicesErr = awsErr(codes.Unavailable, "UNAVAILABLE", "")
	if _, err := admin.ListVirtualMFADevices(
		t.Context(), accountID(t), iam.MFADeviceAssignmentAny, "", 0,
	); err == nil {
		t.Fatal("a failed list returned a page")
	}

	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{{
		Status: &iamv1.MfaDeviceStatus{},
	}}}
	if _, err := admin.ListVirtualMFADevices(
		t.Context(), accountID(t), iam.MFADeviceAssignmentAny, "", 0,
	); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("a device without a serial number mapped to %v", err)
	}

	c, s = harness(t)
	admin = STSAdmin{Client: c}
	const alice = "projects/123456789012/users/alice"
	s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{{
		Status: &iamv1.MfaDeviceStatus{SerialNumber: "arn:vws:iam::123456789012:mfa/a-phone", User: alice},
	}}}
	s.getUserErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if _, err := admin.ListVirtualMFADevices(
		t.Context(), accountID(t), iam.MFADeviceAssignmentAssigned, "", 0,
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("a missing user mapped to %v", err)
	}
}

func TestListVirtualMFADevicesRejectsForeignRows(t *testing.T) {
	const (
		alice   = "projects/123456789012/users/alice"
		foreign = "210987654321"
	)
	for _, tc := range []struct {
		name   string
		device *iamv1.MfaDevice
		user   *iamv1.User
	}{
		{
			name: "device account",
			device: &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: "arn:vws:iam::" + foreign + ":mfa/a-phone",
			}},
		},
		{
			name: "user account",
			device: &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: "arn:vws:iam::123456789012:mfa/a-phone",
				User:         "projects/" + foreign + "/users/alice",
			}},
		},
		{
			name: "user ARN",
			device: &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
				SerialNumber: "arn:vws:iam::123456789012:mfa/a-phone", User: alice,
			}},
			user: &iamv1.User{
				Name: alice, Status: &iamv1.UserStatus{Arn: "arn:vws:iam::" + foreign + ":user/alice"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{tc.device}}
			if tc.user != nil {
				s.getUserRes = map[string]*iamv1.User{tc.user.GetName(): tc.user}
			}
			_, err := (STSAdmin{Client: c}).ListVirtualMFADevices(
				t.Context(), accountID(t), iam.MFADeviceAssignmentAny, "", 0)
			if resource.CodeOf(err) != resource.CodeInternal {
				t.Fatalf("foreign row mapped to %v", err)
			}
		})
	}
}

func TestListVirtualMFADevicesUnassignedSkipsUsers(t *testing.T) {
	c, s := harness(t)
	s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{{
		Status: &iamv1.MfaDeviceStatus{
			SerialNumber: "arn:vws:iam::123456789012:mfa/a-phone",
			User:         "projects/123456789012/users/alice",
		},
	}}}
	s.getUserErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	page, err := (STSAdmin{Client: c}).ListVirtualMFADevices(
		t.Context(), accountID(t), iam.MFADeviceAssignmentUnassigned, "", 0)
	if err != nil || len(page.Devices) != 0 || len(s.getUser) != 0 {
		t.Fatalf("unassigned page %+v, %v; user reads %v", page, err, s.getUser)
	}
}
