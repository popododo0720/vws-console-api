package iamclient

import (
	"testing"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

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
