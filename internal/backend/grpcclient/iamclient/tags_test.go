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

const policyARN = "arn:vws:iam::123456789012:policy/eng/tagged"

func TestTagPolicyOverGRPC(t *testing.T) {
	c, s := harness(t)
	ctx := t.Context()
	admin := STSAdmin{Client: c}
	tags := []iam.Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	err := admin.TagPolicy(ctx, accountID(t), policyARN, tags)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.tagPolicy) != 1 {
		t.Fatalf("sent %v", s.tagPolicy)
	}
	sent := s.tagPolicy[0]
	if sent.GetName() != "projects/123456789012/policies/tagged" {
		t.Errorf("name %q", sent.GetName())
	}
	if len(sent.GetTags()) != 2 || sent.GetTags()[0].GetKey() != "Team" || sent.GetTags()[1].GetValue() != "prod" {
		t.Errorf("tags %v", sent.GetTags())
	}
	if err := admin.UntagPolicy(ctx, accountID(t), policyARN, []string{"Team"}); err != nil {
		t.Fatal(err)
	}
	if len(s.untagPolicy) != 1 || s.untagPolicy[0].GetTagKeys()[0] != "Team" {
		t.Fatalf("untag sent %v", s.untagPolicy)
	}
}

func TestListPolicyTagsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.listTagsRes = &iamv1.ListPolicyTagsResponse{
		Tags:          []*iamv1.Tag{{Key: "Team", Value: "platform"}},
		NextPageToken: "next-token",
	}
	page, err := admin.ListPolicyTags(t.Context(), accountID(t), policyARN, "marker-token", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.listTags) != 1 || s.listTags[0].GetPageToken() != "marker-token" || s.listTags[0].GetPageSize() != 1 {
		t.Fatalf("sent %v", s.listTags)
	}
	if !page.IsTruncated || page.Marker != "next-token" || len(page.Tags) != 1 || page.Tags[0].Key != "Team" {
		t.Fatalf("page %+v", page)
	}
}

func TestPolicyTagErrorsOverGRPC(t *testing.T) {
	c, _ := harness(t)
	admin := STSAdmin{Client: c}
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	err := admin.TagPolicy(t.Context(), accountID(t), "not-an-arn", tags)
	if re := resource.AsError(err); re == nil || re.Code != resource.CodeInvalidArgument {
		t.Fatalf("malformed ARN error %v", err)
	}
	arn := "arn:vws:iam::123456789012:policy/eng/tagged"
	if _, err := admin.ListPolicyTags(t.Context(), accountID(t), arn, "", 2000); err != nil {
		t.Fatalf("list with a large MaxItems: %v", err)
	}
	c, s := harness(t)
	admin = STSAdmin{Client: c}
	s.tagErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if err := admin.TagPolicy(t.Context(), accountID(t), policyARN, tags); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("NoSuchEntity mapped to %v", err)
	}
}

// A running operation is a fault: vws-iam answers tag mutations done.
func TestTagPolicyRunningOperationIsFault(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.tagPolicyRes = &longrunningpb.Operation{Done: false}
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	if err := admin.TagPolicy(t.Context(), accountID(t), policyARN, tags); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("running operation mapped to %v", err)
	}
}

// A failed operation result carries the AWS error in its status.
func TestTagPolicyFailedOperation(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	st, err := status.New(codes.FailedPrecondition, "attached").WithDetails(
		&errdetails.ErrorInfo{
			Reason: "DEPENDENCY_MISSING", Domain: "vws.dev",
			Metadata: map[string]string{"aws_code": "DeleteConflict"},
		})
	if err != nil {
		t.Fatal(err)
	}
	s.tagPolicyRes = &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Error{Error: st.Proto()}}
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	if err := admin.TagPolicy(t.Context(), accountID(t), policyARN, tags); err == nil {
		t.Fatal("failed operation accepted")
	}
}

func accountID(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A policy ARN in another account does not exist for the caller, as in AWS.
func TestPolicyTagOtherAccountIsNotFound(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	other := "arn:vws:iam::210987654321:policy/tagged"
	tags := []iam.Tag{{Key: "k", Value: "v"}}
	if err := admin.TagPolicy(t.Context(), accountID(t), other, tags); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account tag mapped to %v", err)
	}
	page, err := admin.ListPolicyTags(t.Context(), accountID(t), other, "", 0)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account list mapped to %v (%+v)", err, page)
	}
	if len(s.tagPolicy) != 0 || len(s.listTags) != 0 {
		t.Fatalf("a cross-account call reached vws-iam: %v %v", s.tagPolicy, s.listTags)
	}
}
