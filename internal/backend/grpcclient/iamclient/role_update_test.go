package iamclient

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestGetRoleForRoleAuthorization(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	created := time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
	s.getRoleRes = &iamv1.Role{
		Name: "projects/123456789012/roles/ops",
		Spec: &iamv1.RoleSpec{
			Path: "/team/", AssumeRolePolicy: `{"Statement":[]}`, Description: "old",
			MaxSessionDurationSeconds: 3600,
		},
		Status:     &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/team/ops", UniqueId: "AROAOPS"},
		CreateTime: timestamppb.New(created),
	}
	got, err := admin.GetRole(t.Context(), accountID(t), "ops")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.getRole) != 1 || s.getRole[0].GetName() != "projects/123456789012/roles/ops" {
		t.Fatalf("GetRole calls %v", s.getRole)
	}
	want := iam.Role{
		Name: "ops", Path: "/team/", ID: "AROAOPS", ARN: "arn:vws:iam::123456789012:role/team/ops",
		TrustPolicy: `{"Statement":[]}`, Description: "old", MaxSessionDuration: 3600, Created: created,
	}
	if got != want {
		t.Errorf("role %+v, want %+v", got, want)
	}
	s.getRoleErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if _, err := admin.GetRole(t.Context(), accountID(t), "none"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
}

func TestUpdateRoleOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{Name: "projects/123456789012/roles/ops", Spec: &iamv1.RoleSpec{Path: "/team/"}}
	s.updateRoleRes = &longrunningpb.Operation{Done: true}
	description, maxSession := "new", 7200
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{
		Description: &description, MaxSessionDuration: &maxSession,
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 1 {
		t.Fatalf("%d UpdateRole calls, want 1", len(s.updateRole))
	}
	req := s.updateRole[0]
	if req.GetRole().GetName() != "projects/123456789012/roles/ops" {
		t.Errorf("role name %q", req.GetRole().GetName())
	}
	if req.GetRole().GetSpec().GetDescription() != "new" ||
		req.GetRole().GetSpec().GetMaxSessionDurationSeconds() != 7200 {
		t.Errorf("spec %+v", req.GetRole().GetSpec())
	}
	paths := req.GetUpdateMask().GetPaths()
	if len(paths) != 2 || !slices.Contains(paths, "spec.description") ||
		!slices.Contains(paths, "spec.max_session_duration_seconds") {
		t.Errorf("update mask %v", paths)
	}

	description = "newer"
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{Description: &description}); err != nil {
		t.Fatal(err)
	}
	last := s.updateRole[len(s.updateRole)-1]
	if paths := last.GetUpdateMask().GetPaths(); len(paths) != 1 || !slices.Contains(paths, "spec.description") {
		t.Errorf("description-only mask %v", paths)
	}
	maxSession = 3600
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{MaxSessionDuration: &maxSession}); err != nil {
		t.Fatal(err)
	}
	last = s.updateRole[len(s.updateRole)-1]
	if paths := last.GetUpdateMask().GetPaths(); len(paths) != 1 ||
		!slices.Contains(paths, "spec.max_session_duration_seconds") {
		t.Errorf("duration-only mask %v", paths)
	}

	description = ""
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{Description: &description}); err != nil {
		t.Fatal(err)
	}
	last = s.updateRole[len(s.updateRole)-1]
	if last.GetRole().GetSpec().GetDescription() != "" ||
		!slices.Contains(last.GetUpdateMask().GetPaths(), "spec.description") ||
		len(last.GetUpdateMask().GetPaths()) != 1 {
		t.Errorf("empty description update %+v", last)
	}

	before := len(s.updateRole)
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{}); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != before {
		t.Errorf("a no-op update sent %d calls", len(s.updateRole)-before)
	}
}

func TestUpdateRoleErrorsOverGRPC(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	description := "new"
	s.getRoleErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	err := admin.UpdateRole(t.Context(), accountID(t), "none", iam.RoleUpdate{Description: &description})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}

	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{Name: "projects/123456789012/roles/ops", Spec: &iamv1.RoleSpec{Path: "/"}}
	s.updateRoleErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{Description: &description}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("deleted role: %v", err)
	}
	s.updateRoleErr = awsErr(codes.FailedPrecondition, "FAILED_PRECONDITION", "UnmodifiableEntity")
	err = admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{Description: &description})
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	s.updateRoleErr = awsErr(codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{Description: &description}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("validation error: %v", err)
	}
	s.updateRoleErr = nil
	s.updateRoleRes = &longrunningpb.Operation{Done: true}
	long := strings.Repeat("x", iam.MaxRoleDescription+1)
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{Description: &long}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
	low := 3599
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{MaxSessionDuration: &low}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("short session: %v", err)
	}

	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{
		Name: "projects/123456789012/roles/svc",
		Spec: &iamv1.RoleSpec{Path: iam.ServiceLinkedRolePath + "compute.vws/"},
	}
	err = admin.UpdateRole(t.Context(), accountID(t), "svc", iam.RoleUpdate{Description: &description})
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	if len(s.updateRole) != 0 {
		t.Errorf("a service-linked role reached UpdateRole: %v", s.updateRole)
	}

	c, s = harness(t)
	admin = STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{Name: "projects/123456789012/roles/ops", Spec: &iamv1.RoleSpec{Path: "/"}}
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops",
		iam.RoleUpdate{Description: &description}); resource.CodeOf(err) != resource.CodeInternal {
		t.Errorf("missing operation: %v", err)
	}
}
