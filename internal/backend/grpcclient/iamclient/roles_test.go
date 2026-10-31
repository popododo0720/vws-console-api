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

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
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

func TestGetRole(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/ops",
		Spec:   &iamv1.RoleSpec{Path: "/team/", AssumeRolePolicy: `{"Statement":[]}`, Description: "old"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/team/ops", UniqueId: "AROAOPS"},
	}
	opsARN := "arn:vws:iam::123456789012:role/team/ops"
	got, err := admin.GetRole(t.Context(), accountID(t), "ops", backendtest.Grant(t.Context(), t, opsARN))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.getRole) != 1 || s.getRole[0].GetName() != "projects/123456789012/roles/ops" {
		t.Fatalf("GetRole calls %v", s.getRole)
	}
	if got.Path != "/team/" || got.ARN != opsARN || got.Description != "old" {
		t.Errorf("role %+v", got)
	}
	s.getRoleErr = awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	if _, err := admin.GetRole(
		t.Context(),
		accountID(t),
		"none",
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "none"),
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
}

// #358: GetRole answers only the role at the authorized ARN: a role now on
// another path is ConcurrentModification with no data, and the zero
// AuthorizedPrincipal sends nothing.
func TestGetRoleActsOnTheAuthorizedARN(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/ops",
		Spec:   &iamv1.RoleSpec{Path: "/denied/", AssumeRolePolicy: `{"Statement":[]}`},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/denied/ops", UniqueId: "AROAOPS"},
	}
	got, err := admin.GetRole(t.Context(), accountID(t), "ops",
		backendtest.Grant(t.Context(), t, "arn:vws:iam::123456789012:role/team/ops"))
	if !iam.IsChanged(err) || got != (iam.Role{}) {
		t.Fatalf("GetRole of a moved role = %+v, %v; want ConcurrentModification and no role", got, err)
	}
	sent := len(s.getRole)
	if _, err := admin.GetRole(
		t.Context(),
		accountID(t),
		"ops",
		iam.AuthorizedPrincipal{},
	); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("GetRole with the zero AuthorizedPrincipal: %v", err)
	}
	if len(s.getRole) != sent {
		t.Fatalf("GetRole with the zero AuthorizedPrincipal sent %d requests", len(s.getRole)-sent)
	}
}

func TestUpdateRole(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/ops",
		Spec:   &iamv1.RoleSpec{Path: "/"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops"},
	}
	s.updateRoleRes = &longrunningpb.Operation{Done: true}
	description := "new"
	seconds := 3600
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{
		Description: &description, MaxSessionDuration: &seconds,
	}, backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops")); err != nil {
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
		req.GetRole().GetSpec().GetMaxSessionDurationSeconds() != 3600 {
		t.Errorf("role spec %+v", req.GetRole().GetSpec())
	}
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 2 ||
		paths[0] != "spec.description" || paths[1] != "spec.max_session_duration_seconds" {
		t.Errorf("update mask %v", paths)
	}

	s.updateRole = nil
	seconds = 43200
	if err := admin.UpdateRole(t.Context(), accountID(t), "ops", iam.RoleUpdate{
		MaxSessionDuration: &seconds,
	}, backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops")); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 1 {
		t.Fatalf("%d UpdateRole calls, want 1", len(s.updateRole))
	}
	req = s.updateRole[0]
	if req.GetRole().GetSpec().GetDescription() != "" ||
		req.GetRole().GetSpec().GetMaxSessionDurationSeconds() != 43200 {
		t.Errorf("role spec %+v", req.GetRole().GetSpec())
	}
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 ||
		paths[0] != "spec.max_session_duration_seconds" {
		t.Errorf("update mask %v, want [spec.max_session_duration_seconds]", paths)
	}

	s.updateRole = nil
	empty := ""
	if err := admin.UpdateRole(
		t.Context(),
		accountID(t),
		"ops",
		iam.RoleUpdate{Description: &empty},
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 1 {
		t.Fatalf("%d UpdateRole calls, want 1", len(s.updateRole))
	}
	req = s.updateRole[0]
	if req.GetRole().GetSpec().GetDescription() != "" {
		t.Errorf("description %q, want empty", req.GetRole().GetSpec().GetDescription())
	}
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "spec.description" {
		t.Errorf("update mask %v, want [spec.description]", paths)
	}

	s.updateRole = nil
	if err := admin.UpdateRole(
		t.Context(), accountID(t), "ops", iam.RoleUpdate{}, backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 0 {
		t.Errorf("a no-op update reached UpdateRole: %v", s.updateRole)
	}
}

func TestUpdateRoleErrors(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleErr = awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	err := admin.UpdateRole(
		t.Context(),
		accountID(t),
		"none",
		iam.RoleUpdate{},
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "none"),
	)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	s.getRoleErr = nil
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/svc",
		Spec:   &iamv1.RoleSpec{Path: iam.ServiceLinkedRolePath + "compute.vws/"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role" + iam.ServiceLinkedRolePath + "compute.vws/" + "svc"},
	}
	err = admin.UpdateRole(
		t.Context(), accountID(t), "svc", iam.RoleUpdate{}, backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "svc"),
	)
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	if len(s.updateRole) != 0 {
		t.Errorf("a service-linked role reached UpdateRole: %v", s.updateRole)
	}

	s.getRoleRes = &iamv1.Role{
		Spec: &iamv1.RoleSpec{Path: "/"}, Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops"},
	}
	long := strings.Repeat("x", iam.MaxRoleDescription+1)
	err = admin.UpdateRole(
		t.Context(),
		accountID(t),
		"ops",
		iam.RoleUpdate{Description: &long},
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
	short := 3599
	err = admin.UpdateRole(
		t.Context(),
		accountID(t),
		"ops",
		iam.RoleUpdate{MaxSessionDuration: &short},
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("short duration: %v", err)
	}
	if len(s.updateRole) != 0 {
		t.Errorf("invalid input reached UpdateRole: %v", s.updateRole)
	}

	s.updateRoleErr = awsErr(codes.FailedPrecondition, "FAILED_PRECONDITION", "UnmodifiableEntity")
	description := "new"
	err = admin.UpdateRole(
		t.Context(),
		accountID(t),
		"ops",
		iam.RoleUpdate{Description: &description},
		backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("vws-iam rejection: %+v", err)
	}
}

func TestUpdateRoleDescription(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	created := time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/ops",
		Spec:   &iamv1.RoleSpec{Path: "/", Description: "old"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops"},
	}
	s.updateRoleRes = roleOperation(t, &iamv1.Role{
		Name: "projects/123456789012/roles/ops",
		Spec: &iamv1.RoleSpec{
			Path: "/", AssumeRolePolicy: `{"Statement":[{"Effect":"Allow"}]}`,
			Description: "new", MaxSessionDurationSeconds: 3600,
		},
		Status:     &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops", UniqueId: "AROAOPS"},
		CreateTime: timestamppb.New(created),
	})
	got, err := admin.UpdateRoleDescription(
		t.Context(), accountID(t), "ops", "new", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
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

func TestUpdateRoleDescriptionEmpty(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	role := &iamv1.Role{
		Name:   "projects/123456789012/roles/ops",
		Spec:   &iamv1.RoleSpec{Path: "/", Description: "old"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops"},
	}
	s.getRoleRes = role
	s.updateRoleRes = roleOperation(t, &iamv1.Role{
		Name: "projects/123456789012/roles/ops",
		Spec: &iamv1.RoleSpec{Path: "/"},
	})
	// Clearing a field is still an update, so its mask path must stay.
	if _, err := admin.UpdateRoleDescription(
		t.Context(), accountID(t), "ops", "", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	); err != nil {
		t.Fatal(err)
	}
	if len(s.updateRole) != 1 {
		t.Fatalf("%d UpdateRole calls, want 1", len(s.updateRole))
	}
	req := s.updateRole[0]
	if req.GetRole().GetSpec().GetDescription() != "" {
		t.Errorf("description %q, want empty", req.GetRole().GetSpec().GetDescription())
	}
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "spec.description" {
		t.Errorf("update mask %v, want [spec.description]", paths)
	}
}

func TestUpdateRoleDescriptionRejectsServiceLinkedRole(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/svc",
		Spec:   &iamv1.RoleSpec{Path: iam.ServiceLinkedRolePath + "compute.vws/"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role" + iam.ServiceLinkedRolePath + "compute.vws/" + "svc"},
	}
	_, err := admin.UpdateRoleDescription(
		t.Context(), accountID(t), "svc", "new", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "svc"),
	)
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	if len(s.updateRole) != 0 {
		t.Errorf("a service-linked role reached UpdateRole: %v", s.updateRole)
	}
}

func TestUpdateRoleDescriptionErrors(t *testing.T) {
	c, s := harness(t)
	admin := STSAdmin{Client: c}
	// The role read before the change; its ARN is the one each call is
	// authorized on, so only the UpdateRole answer varies.
	s.getRoleRes = &iamv1.Role{
		Spec: &iamv1.RoleSpec{Path: "/"}, Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/ops"},
	}
	s.updateRoleErr = awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	_, err := admin.UpdateRoleDescription(
		t.Context(), accountID(t), "none", "new", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "none"),
	)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	s.updateRoleErr = nil
	s.updateRoleRes = &longrunningpb.Operation{Done: true}
	_, err = admin.UpdateRoleDescription(
		t.Context(), accountID(t), "ops", "new", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Errorf("missing role response: %v", err)
	}
	s.updateRoleRes = nil
	s.updateRoleErr = awsErr(codes.FailedPrecondition, "FAILED_PRECONDITION", "UnmodifiableEntity")
	_, err = admin.UpdateRoleDescription(
		t.Context(), accountID(t), "svc", "new", backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "svc"),
	)
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeConflict || re.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	s.updateRoleErr = nil
	long := strings.Repeat("x", iam.MaxRoleDescription+1)
	_, err = admin.UpdateRoleDescription(
		t.Context(), accountID(t), "ops", long, backendtest.RoleGrant(t.Context(), t, admin, accountID(t), "ops"),
	)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
}
