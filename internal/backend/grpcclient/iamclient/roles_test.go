package iamclient

import (
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func roleOperation(t *testing.T, role *iamv1.Role) *longrunningpb.Operation {
	t.Helper()
	response, err := anypb.New(role)
	if err != nil {
		t.Fatal(err)
	}
	return &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Response{Response: response}}
}

func TestUpdateRoleDescription(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	created := time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
	s.updateRoleRes = roleOperation(t, &iamv1.Role{
		Name: "projects/123456789012/roles/ops",
		Spec: &iamv1.RoleSpec{
			Path: "/", AssumeRolePolicy: `{"Statement":[{"Effect":"Allow"}]}`,
			Description: "new", MaxSessionDurationSeconds: 3600,
		},
		Status:     &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops", UniqueId: "AROAOPS"},
		CreateTime: timestamppb.New(created),
	})
	got, err := admin.UpdateRoleDescription(t.Context(), accountID(t), "ops", "new")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 1 {
		t.Fatalf("%d UpdateRole calls, want 1", len(s.updateRole))
	}
	req := s.updateRole[0]
	if req.GetRole().GetName() != "projects/123456789012/roles/ops" {
		t.Errorf("role name %q", req.GetRole().GetName())
	}
	if req.GetRole().GetSpec().GetDescription() != "new" {
		t.Errorf("description %q", req.GetRole().GetSpec().GetDescription())
	}
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "spec.description" {
		t.Errorf("update mask %v, want [spec.description]", paths)
	}
	want := iam.Role{
		Name: "ops", Path: "/", ID: "AROAOPS", ARN: "arn:vws:iam::123456789012:role/ops",
		TrustPolicy: `{"Statement":[{"Effect":"Allow"}]}`, Description: "new",
		MaxSessionDuration: 3600, Created: created,
	}
	if got != want {
		t.Errorf("role %+v, want %+v", got, want)
	}
}

func TestUpdateRoleDescriptionErrors(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.updateRoleErr = awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	_, err := admin.UpdateRoleDescription(t.Context(), accountID(t), "none", "new")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	s.updateRoleErr = nil
	s.updateRoleRes = &longrunningpb.Operation{Done: true}
	_, err = admin.UpdateRoleDescription(t.Context(), accountID(t), "ops", "new")
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Errorf("missing role response: %v", err)
	}
	s.updateRoleRes = nil
	s.updateRoleErr = awsErr(codes.FailedPrecondition, "FAILED_PRECONDITION", "UnmodifiableEntity")
	_, err = admin.UpdateRoleDescription(t.Context(), accountID(t), "svc", "new")
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	s.updateRoleErr = nil
	long := strings.Repeat("x", iam.MaxRoleDescription+1)
	_, err = admin.UpdateRoleDescription(t.Context(), accountID(t), "ops", long)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
}
