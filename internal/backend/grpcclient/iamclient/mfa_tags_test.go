package iamclient

import (
	"strings"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	mfaSerial  = "arn:vws:iam::123456789012:mfa/alice-phone"
	mfaForeign = "arn:vws:iam::210987654321:mfa/alice-phone"
)

func TestTagMFADeviceOverGRPC(t *testing.T) {
	c, s := harness(t)
	ctx := t.Context()
	admin := STSAdmin{Client: c}
	tags := []iam.Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	if err := admin.TagMFADevice(ctx, accountID(t), mfaSerial, tags); err != nil {
		t.Fatal(err)
	}
	if len(s.tagMfa) != 1 {
		t.Fatalf("sent %v", s.tagMfa)
	}
	sent := s.tagMfa[0]
	if sent.GetName() != "projects/123456789012/mfaDevices/alice-phone" {
		t.Errorf("name %q", sent.GetName())
	}
	if len(sent.GetTags()) != 2 || sent.GetTags()[0].GetKey() != "Team" || sent.GetTags()[1].GetValue() != "prod" {
		t.Errorf("tags %v", sent.GetTags())
	}
	if err := admin.UntagMFADevice(ctx, accountID(t), mfaSerial, []string{"Team"}); err != nil {
		t.Fatal(err)
	}
	if len(s.untagMfa) != 1 || s.untagMfa[0].GetTagKeys()[0] != "Team" {
		t.Fatalf("untag sent %v", s.untagMfa)
	}
}

func TestListMFADeviceTagsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.listMfaTagRes = &iamv1.ListMFADeviceTagsResponse{
		Tags:          []*iamv1.Tag{{Key: "Team", Value: "platform"}},
		NextPageToken: "next-token",
	}
	page, err := admin.ListMFADeviceTags(t.Context(), accountID(t), mfaSerial, "marker-token", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.listMfaTags) != 1 || s.listMfaTags[0].GetPageToken() != "marker-token" ||
		s.listMfaTags[0].GetPageSize() != 1 {
		t.Fatalf("sent %v", s.listMfaTags)
	}
	if !page.IsTruncated || page.Marker != "next-token" || len(page.Tags) != 1 || page.Tags[0].Key != "Team" {
		t.Fatalf("page %+v", page)
	}
}

func TestMFADeviceTagErrorsOverGRPC(t *testing.T) {
	c, _ := harness(t)
	admin := STSAdmin{Client: c}
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	// A serial that names no device of the caller does not exist, as in AWS.
	for _, serial := range []string{"not-an-arn", "arn:vws:iam::123456789012:policy/tagged", mfaForeign} {
		if err := admin.TagMFADevice(t.Context(), accountID(t), serial, tags); resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("serial %q mapped to %v", serial, err)
		}
	}
	c, s := harness(t)
	admin = STSAdmin{Client: c}
	s.mfaTagErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	err := admin.TagMFADevice(t.Context(), accountID(t), mfaSerial, tags)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("NoSuchEntity mapped to %v", err)
	}
}

// An invalid Tags or TagKeys request is a ValidationError before vws-iam is
// called, as the fake answers it on a direct Admin call.
func TestMFADeviceTagValidationOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	for _, tc := range []struct {
		name  string
		tags  []iam.Tag
		field string
	}{
		{"bad key character", []iam.Tag{{Key: "bad#key", Value: "v"}}, "tags.member.key"},
		{"key too long", []iam.Tag{{Key: strings.Repeat("k", iam.MaxTagKeyLen+1), Value: "v"}}, "tags.member.key"},
		{"bad value character", []iam.Tag{{Key: "k", Value: "bad#value"}}, "tags.member.value"},
		{"value too long", []iam.Tag{{Key: "k", Value: strings.Repeat("v", iam.MaxTagValueLen+1)}}, "tags.member.value"},
		{"empty list", nil, "tags"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := admin.TagMFADevice(t.Context(), accountID(t), mfaSerial, tc.tags)
			if re := resource.AsError(err); re == nil || re.Code != resource.CodeInvalidArgument || re.Field != tc.field {
				t.Fatalf("TagMFADevice error %v, want InvalidArgument at %s", err, tc.field)
			}
		})
	}
	if len(s.tagMfa) != 0 {
		t.Fatalf("an invalid tag reached vws-iam: %v", s.tagMfa)
	}
	for _, tc := range []struct {
		name  string
		keys  []string
		field string
	}{
		{"bad key character", []string{"bad#key"}, "tagKeys.member"},
		{"key too long", []string{strings.Repeat("k", iam.MaxTagKeyLen+1)}, "tagKeys.member"},
		{"empty key", []string{""}, "tagKeys.member"},
		{"empty list", nil, "tagKeys"},
	} {
		t.Run("untag "+tc.name, func(t *testing.T) {
			err := admin.UntagMFADevice(t.Context(), accountID(t), mfaSerial, tc.keys)
			if re := resource.AsError(err); re == nil || re.Code != resource.CodeInvalidArgument || re.Field != tc.field {
				t.Fatalf("UntagMFADevice error %v, want InvalidArgument at %s", err, tc.field)
			}
		})
	}
	if len(s.untagMfa) != 0 {
		t.Fatalf("an invalid tag key reached vws-iam: %v", s.untagMfa)
	}
}

// A running operation is a fault: vws-iam answers tag mutations done.
func TestMFADeviceTagRunningOperationIsFault(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.tagMfaRes = &longrunningpb.Operation{Done: false}
	err := admin.TagMFADevice(t.Context(), accountID(t), mfaSerial, []iam.Tag{{Key: "k", Value: "v"}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("running operation mapped to %v", err)
	}
}

// A failed operation result carries the AWS error in its status.
func TestMFADeviceTagFailedOperation(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	st, err := status.New(codes.FailedPrecondition, "locked").WithDetails(
		&errdetails.ErrorInfo{
			Reason: "DEPENDENCY_MISSING", Domain: "vws.dev",
			Metadata: map[string]string{"aws_code": "DeleteConflict"},
		})
	if err != nil {
		t.Fatal(err)
	}
	s.tagMfaRes = &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Error{Error: st.Proto()}}
	if err := admin.TagMFADevice(t.Context(), accountID(t), mfaSerial, []iam.Tag{{Key: "k", Value: "v"}}); err == nil {
		t.Fatal("failed operation accepted")
	}
}

// A serial number in another account does not exist for the caller, as in AWS,
// and the call never reaches vws-iam.
func TestMFADeviceTagOtherAccountIsNotFound(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	err := admin.TagMFADevice(t.Context(), accountID(t), mfaForeign, tags)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account tag mapped to %v", err)
	}
	page, err := admin.ListMFADeviceTags(t.Context(), accountID(t), mfaForeign, "", 0)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account list mapped to %v (%+v)", err, page)
	}
	if len(s.tagMfa) != 0 || len(s.listMfaTags) != 0 {
		t.Fatalf("a cross-account call reached vws-iam: %v %v", s.tagMfa, s.listMfaTags)
	}
}

// A device is addressed by the name in its resource on the vws-iam wire, so
// the client must check that the stored serial number is the serial number the
// caller sent. Otherwise a serial for another partition, region or path
// reaches the same device.
func TestMFADeviceTagWrongSerialIsNotFound(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getMfaRes = &iamv1.MfaDevice{
		Name:   "projects/123456789012/mfaDevices/alice-phone",
		Status: &iamv1.MfaDeviceStatus{SerialNumber: mfaSerial},
	}
	variants := []struct {
		name   string
		serial string
	}{
		{"partition", "arn:aws:iam::123456789012:mfa/alice-phone"},
		{"region", "arn:vws:iam:us-east-1:123456789012:mfa/alice-phone"},
		{"path", "arn:vws:iam::123456789012:mfa/admin/alice-phone"},
	}
	ctx := t.Context()
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			tags := []iam.Tag{{Key: "k", Value: "v"}}
			if err := admin.TagMFADevice(ctx, accountID(t), v.serial, tags); resource.CodeOf(err) != resource.CodeNotFound {
				t.Fatalf("wrong serial tag mapped to %v", err)
			}
			err := admin.UntagMFADevice(ctx, accountID(t), v.serial, []string{"k"})
			if resource.CodeOf(err) != resource.CodeNotFound {
				t.Fatalf("wrong serial untag mapped to %v", err)
			}
			_, err = admin.ListMFADeviceTags(ctx, accountID(t), v.serial, "", 0)
			if resource.CodeOf(err) != resource.CodeNotFound {
				t.Fatalf("wrong serial list mapped to %v", err)
			}
		})
	}
	if len(s.tagMfa)+len(s.untagMfa)+len(s.listMfaTags) != 0 {
		t.Fatalf("a wrong-serial call reached a tag action: %v %v %v", s.tagMfa, s.untagMfa, s.listMfaTags)
	}
	if len(s.getMfa) != 3*len(variants) {
		t.Fatalf("looked the device up %d times, want %d", len(s.getMfa), 3*len(variants))
	}
	for _, req := range s.getMfa {
		if got := req.GetName(); got != "projects/123456789012/mfaDevices/alice-phone" {
			t.Fatalf("looked up %q", got)
		}
	}
}

// A vws-iam NotFound on the device lookup is the same NoSuchEntity answer as a
// serial that does not match, and no tag action runs.
func TestMFADeviceTagLookupNotFoundIsNotFound(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	ctx := t.Context()
	s.getMfaErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	if err := admin.TagMFADevice(ctx, accountID(t), mfaSerial, tags); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing device tag mapped to %v", err)
	}
	err := admin.UntagMFADevice(ctx, accountID(t), mfaSerial, []string{"k"})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing device untag mapped to %v", err)
	}
	_, err = admin.ListMFADeviceTags(ctx, accountID(t), mfaSerial, "", 0)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing device list mapped to %v", err)
	}
	if len(s.tagMfa)+len(s.untagMfa)+len(s.listMfaTags) != 0 {
		t.Fatalf("a missing-device call reached a tag action: %v %v %v", s.tagMfa, s.untagMfa, s.listMfaTags)
	}
	if len(s.getMfa) != 3 {
		t.Fatalf("looked the device up %d times, want 3", len(s.getMfa))
	}
}
