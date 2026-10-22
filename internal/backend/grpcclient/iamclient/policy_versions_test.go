package iamclient

import (
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestDeletePolicyVersionOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	if err := admin.DeletePolicyVersion(t.Context(), accountID(t), policyARN, "v2"); err != nil {
		t.Fatal(err)
	}
	if len(s.deleteVersion) != 1 {
		t.Fatalf("sent %v", s.deleteVersion)
	}
	if got := s.deleteVersion[0].GetName(); got != "projects/123456789012/policies/tagged/versions/v2" {
		t.Errorf("name %q", got)
	}
}

func TestDeletePolicyVersionDefaultIsConflict(t *testing.T) {
	c, s := harness(t)
	st, err := status.New(codes.FailedPrecondition, "default version").WithDetails(
		&errdetails.ErrorInfo{
			Reason: "DEPENDENCY_MISSING", Domain: "vws.dev",
			Metadata: map[string]string{"aws_code": "DeleteConflict"},
		})
	if err != nil {
		t.Fatal(err)
	}
	s.deleteVersionRes = &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Error{Error: st.Proto()}}
	admin := STSAdmin{Client: c}
	err = admin.DeletePolicyVersion(t.Context(), accountID(t), policyARN, "v1")
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("default version mapped to %v", err)
	}
}

func TestDeletePolicyVersionMissingIsNotFound(t *testing.T) {
	c, s := harness(t)
	s.deleteVersionErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	admin := STSAdmin{Client: c}
	err := admin.DeletePolicyVersion(t.Context(), accountID(t), policyARN, "v2")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing version mapped to %v", err)
	}
	if len(s.deleteVersion) != 1 {
		t.Fatalf("delete RPC calls %v, want 1", s.deleteVersion)
	}
}

func TestDeletePolicyVersionRunningOperationIsFault(t *testing.T) {
	c, s := harness(t)
	s.deleteVersionRes = &longrunningpb.Operation{Done: false}
	admin := STSAdmin{Client: c}
	err := admin.DeletePolicyVersion(t.Context(), accountID(t), policyARN, "v2")
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("running operation mapped to %v", err)
	}
}

// Only DeleteConflict is a resource conflict. Any other precondition is a
// fault, not a 409.
func TestDeletePolicyVersionOtherPreconditionIsFault(t *testing.T) {
	c, s := harness(t)
	st, err := status.New(codes.FailedPrecondition, "etag mismatch").WithDetails(
		&errdetails.ErrorInfo{
			Reason: "GENERATION_CONFLICT", Domain: "vws.dev",
			Metadata: map[string]string{"aws_code": "ConcurrentModification"},
		})
	if err != nil {
		t.Fatal(err)
	}
	s.deleteVersionRes = &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Error{Error: st.Proto()}}
	admin := STSAdmin{Client: c}
	err = admin.DeletePolicyVersion(t.Context(), accountID(t), policyARN, "v2")
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("other precondition mapped to %v", err)
	}
}

// A policy is addressed by name on the vws-iam wire, so the client must check
// that the stored policy ARN, path included, is the ARN the caller sent.
func TestDeletePolicyVersionWrongPathIsNotFound(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	stored := "arn:vws:iam::123456789012:policy/admin/tagged"
	wrong := "arn:vws:iam::123456789012:policy/team/tagged"
	s.getPolicyRes = &iamv1.Policy{
		Name:   "projects/123456789012/policies/tagged",
		Status: &iamv1.PolicyStatus{Arn: stored},
	}
	err := admin.DeletePolicyVersion(t.Context(), accountID(t), wrong, "v2")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("wrong path delete mapped to %v", err)
	}
	if len(s.deleteVersion) != 0 {
		t.Fatalf("a wrong-path call reached vws-iam: %v", s.deleteVersion)
	}
}

func TestDeletePolicyVersionMalformedARN(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	err := admin.DeletePolicyVersion(t.Context(), accountID(t), "not-an-arn", "v2")
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("malformed ARN mapped to %v", err)
	}
	if len(s.deleteVersion) != 0 {
		t.Fatalf("a malformed-ARN call reached vws-iam: %v", s.deleteVersion)
	}
}
