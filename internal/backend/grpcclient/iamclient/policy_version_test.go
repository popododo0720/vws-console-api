package iamclient

import (
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestListPolicyVersionsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	created := time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
	s.listVersionsRes = &iamv1.ListPolicyVersionsResponse{
		PolicyVersions: []*iamv1.PolicyVersion{{
			Name:       "projects/123456789012/policies/tagged/versions/v1",
			Status:     &iamv1.PolicyVersionStatus{DefaultVersion: true},
			CreateTime: timestamppb.New(created),
		}},
		NextPageToken: "next-token",
	}
	page, err := admin.ListPolicyVersions(t.Context(), accountID(t), policyARN, "marker-token", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.listVersions) != 1 {
		t.Fatalf("sent %v", s.listVersions)
	}
	sent := s.listVersions[0]
	if got := sent.GetParent(); got != "projects/123456789012/policies/tagged" {
		t.Errorf("parent %q", got)
	}
	if sent.GetPageToken() != "marker-token" || sent.GetPageSize() != 1 {
		t.Errorf("paging %v", sent)
	}
	if !page.IsTruncated || page.Marker != "next-token" || len(page.Versions) != 1 {
		t.Fatalf("page %+v", page)
	}
	v := page.Versions[0]
	if v.ID != "v1" || !v.IsDefaultVersion || !v.Created.Equal(created) {
		t.Errorf("version %+v", v)
	}
}

func TestListPolicyVersionsErrorsOverGRPC(t *testing.T) {
	c, _ := harness(t)
	admin := STSAdmin{Client: c}
	_, err := admin.ListPolicyVersions(t.Context(), accountID(t), "not-an-arn", "", 0)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed ARN: %v", err)
	}
	c, s := harness(t)
	admin = STSAdmin{Client: c}
	s.listVersionsErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = admin.ListPolicyVersions(t.Context(), accountID(t), policyARN, "", 0)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing policy: %v", err)
	}
	// vws-iam addresses a policy by name, so a wrong path in the ARN must not
	// reach the policy behind it.
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getPolicyRes = &iamv1.Policy{
		Name:   "projects/123456789012/policies/tagged",
		Status: &iamv1.PolicyStatus{Arn: "arn:vws:iam::123456789012:policy/admin/tagged"},
	}
	wrong := "arn:vws:iam::123456789012:policy/team/tagged"
	_, err = admin.ListPolicyVersions(t.Context(), accountID(t), wrong, "", 0)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("wrong path: %v", err)
	}
	if len(s.listVersions) != 0 {
		t.Errorf("a wrong-path call reached ListPolicyVersions: %v", s.listVersions)
	}
}

func TestCreatePolicyVersionOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	created := time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
	version := &iamv1.PolicyVersion{
		Name:       "projects/123456789012/policies/tagged/versions/v2",
		Spec:       &iamv1.PolicyVersionSpec{Document: "{}"},
		Status:     &iamv1.PolicyVersionStatus{DefaultVersion: true},
		CreateTime: timestamppb.New(created),
	}
	response, err := anypb.New(version)
	if err != nil {
		t.Fatal(err)
	}
	s.createVersionRes = &longrunningpb.Operation{
		Done: true, Result: &longrunningpb.Operation_Response{Response: response},
	}
	got, err := admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{}", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.createVersion) != 1 {
		t.Fatalf("sent %v", s.createVersion)
	}
	sent := s.createVersion[0]
	if got := sent.GetParent(); got != "projects/123456789012/policies/tagged" {
		t.Errorf("parent %q", got)
	}
	if sent.GetPolicyVersion().GetSpec().GetDocument() != "{}" || !sent.GetPolicyVersion().GetSpec().GetSetAsDefault() {
		t.Errorf("version spec %v", sent.GetPolicyVersion().GetSpec())
	}
	if got.ID != "v2" || !got.IsDefaultVersion || !got.Created.Equal(created) {
		t.Errorf("version %+v", got)
	}
	if len(s.getPolicy) != 1 {
		t.Errorf("policy lookups %v, want one", s.getPolicy)
	}
}

func TestCreatePolicyVersionErrorsOverGRPC(t *testing.T) {
	c, _ := harness(t)
	admin := STSAdmin{Client: c}
	_, err := admin.CreatePolicyVersion(t.Context(), accountID(t), "not-an-arn", "{}", false)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed ARN: %v", err)
	}
	c, s := harness(t)
	admin = STSAdmin{Client: c}
	s.getPolicyErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{}", false)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing policy: %v", err)
	}
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.createVersionErr = awsErr(codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument")
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{", false)
	if re := resource.AsError(err); re == nil || re.Code != resource.CodeInvalidArgument || re.Field != "PolicyDocument" {
		t.Errorf("malformed document: %v, want PolicyDocument", err)
	}
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.createVersionErr = awsErr(codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{}", false)
	if resource.CodeOf(err) != resource.CodeResourceExhausted {
		t.Errorf("sixth version: %v", err)
	}
	// A running operation is a fault, and a finished one with no version is too.
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.createVersionRes = &longrunningpb.Operation{}
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{}", false)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Errorf("running operation: %v", err)
	}
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.createVersionRes = &longrunningpb.Operation{Done: true}
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), policyARN, "{}", false)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Errorf("missing version: %v", err)
	}
	// vws-iam addresses a policy by name, so a wrong path in the ARN must not
	// reach the policy behind it.
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getPolicyRes = &iamv1.Policy{
		Name:   "projects/123456789012/policies/tagged",
		Status: &iamv1.PolicyStatus{Arn: "arn:vws:iam::123456789012:policy/admin/tagged"},
	}
	wrong := "arn:vws:iam::123456789012:policy/team/tagged"
	_, err = admin.CreatePolicyVersion(t.Context(), accountID(t), wrong, "{}", false)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("wrong path: %v", err)
	}
	if len(s.createVersion) != 0 {
		t.Errorf("a wrong-path call reached CreatePolicyVersion: %v", s.createVersion)
	}
}

func TestSetDefaultPolicyVersionOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	if err := admin.SetDefaultPolicyVersion(t.Context(), accountID(t), policyARN, "v2"); err != nil {
		t.Fatal(err)
	}
	if len(s.updatePolicy) != 1 {
		t.Fatalf("sent %d UpdatePolicy calls, want 1", len(s.updatePolicy))
	}
	sent := s.updatePolicy[0]
	wantName := "projects/123456789012/policies/tagged"
	if got := sent.GetPolicy().GetName(); got != wantName {
		t.Errorf("name %q, want %q", got, wantName)
	}
	if got := sent.GetPolicy().GetSpec().GetDefaultVersion(); got != "v2" {
		t.Errorf("default version %q, want v2", got)
	}
	if mask := sent.GetUpdateMask().GetPaths(); len(mask) != 1 || mask[0] != "spec.default_version" {
		t.Errorf("mask %v, want [spec.default_version]", mask)
	}
	if len(s.getPolicy) != 1 || s.getPolicy[0].GetName() != wantName {
		t.Errorf("lookup %v, want one for %q", s.getPolicy, wantName)
	}
}

func TestSetDefaultPolicyVersionErrorsOverGRPC(t *testing.T) {
	c, _ := harness(t)
	admin := STSAdmin{Client: c}
	err := admin.SetDefaultPolicyVersion(t.Context(), accountID(t), "not-an-arn", "v1")
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed ARN: %v", err)
	}
	c, s := harness(t)
	admin = STSAdmin{Client: c}
	s.updateErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	err = admin.SetDefaultPolicyVersion(t.Context(), accountID(t), policyARN, "v9")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing version: %v", err)
	}
	// vws-iam addresses a policy by name, so a wrong path in the ARN must not
	// reach the policy behind it.
	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getPolicyRes = &iamv1.Policy{
		Name:   "projects/123456789012/policies/tagged",
		Status: &iamv1.PolicyStatus{Arn: "arn:vws:iam::123456789012:policy/admin/tagged"},
	}
	wrong := "arn:vws:iam::123456789012:policy/team/tagged"
	err = admin.SetDefaultPolicyVersion(t.Context(), accountID(t), wrong, "v1")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("wrong path: %v", err)
	}
	if len(s.updatePolicy) != 0 {
		t.Errorf("a wrong-path call reached UpdatePolicy: %v", s.updatePolicy)
	}
}
