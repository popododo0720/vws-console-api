package iamclient

import (
	"context"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	lifecycleTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"compute.vws"},"Action":"sts:AssumeRole"}]}`
	lifecycleTrust2 = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"storage.vws"},"Action":"sts:AssumeRole"}]}`
	opsRoleARN = "arn:vws:iam::123456789012:role/svc/ops"
)

// seededRoles is an STSAdmin over a directory holding the role ops (/svc/).
func seededRoles(ctx context.Context, t *testing.T) (STSAdmin, *directory) {
	t.Helper()
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	if _, err := a.CreateRole(ctx, account314, iam.RoleInput{
		Name: "ops", Path: "/svc/", TrustPolicy: lifecycleTrust,
	}); err != nil {
		t.Fatalf("seed CreateRole: %v", err)
	}
	return a, d
}

func (d *directory) role(name string) *dirEntity {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.roles[fold("projects/123456789012/roles/"+name)]
}

func TestRoleCreateRetriesSafely(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	d.mu.Lock()
	d.failAfter["CreateRole"] = 1 // applied, then the reply is lost
	d.mu.Unlock()
	r, err := a.CreateRole(ctx, account314, iam.RoleInput{Name: "web", TrustPolicy: lifecycleTrust})
	if err != nil || r.ARN != "arn:vws:iam::123456789012:role/web" {
		t.Fatalf("CreateRole: %+v %v", r, err)
	}
	sent := d.sent("CreateRole")
	first, second := sent[len(sent)-2].(*iamv1.CreateRoleRequest), sent[len(sent)-1].(*iamv1.CreateRoleRequest)
	if first.GetRequestId() == "" || first.GetRequestId() != second.GetRequestId() {
		t.Errorf("retry used request ids %q and %q", first.GetRequestId(), second.GetRequestId())
	}
	if s := second.GetRole().GetSpec(); s.GetPath() != "/" || s.GetMaxSessionDurationSeconds() != 3600 ||
		s.GetAssumeRolePolicy() != lifecycleTrust || second.GetParent() != "projects/123456789012" ||
		second.GetRoleId() != "web" {
		t.Errorf("CreateRole request: %v", second)
	}
}

func TestRoleCreateChecksBeforeSending(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	for _, in := range []iam.RoleInput{
		{Name: "web", TrustPolicy: "{not json"},
		{Name: "a/b", TrustPolicy: lifecycleTrust},
		{Name: "web", TrustPolicy: lifecycleTrust, MaxSessionDuration: 43201},
	} {
		if _, err := a.CreateRole(ctx, account314, in); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("CreateRole %+v: %v", in, err)
		}
	}
	if n := len(d.sent("CreateRole")); n != 1 {
		t.Errorf("sent %d CreateRole, want only the seed", n)
	}
}

func TestRoleListReadsEveryPage(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	for _, n := range []string{"b", "c"} {
		if _, err := a.CreateRole(ctx, account314, iam.RoleInput{Name: n, TrustPolicy: lifecycleTrust}); err != nil {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	d.maxPage = 1
	d.mu.Unlock()
	rs, err := a.ListRoles(ctx, account314, "")
	if err != nil || len(rs) != 3 || rs[0].Name != "b" || rs[1].Name != "c" || rs[2].Name != "ops" {
		t.Fatalf("ListRoles: %+v %v", rs, err)
	}
	if n := len(d.sent("ListRoles")); n != 3 {
		t.Errorf("sent %d ListRoles, want 3 pages", n)
	}
}

func TestRoleListSkipsARoleWithNoARN(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	if _, err := a.CreateRole(ctx, account314, iam.RoleInput{Name: "web", TrustPolicy: lifecycleTrust}); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.roles[fold("projects/123456789012/roles/web")].noARN = true
	d.mu.Unlock()
	rs, err := a.ListRoles(ctx, account314, "")
	if err != nil || len(rs) != 1 || rs[0].Name != "ops" {
		t.Fatalf("ListRoles: %+v %v, want only ops", rs, err)
	}
}

// AC2: a write that loses the etag race reads the role again and writes under
// the new etag; one that keeps losing is ConcurrentModification and changes
// nothing.
func TestTrustPolicyRereadsALostRace(t *testing.T) {
	ctx := t.Context()
	t.Run("one lost race", func(t *testing.T) {
		a, d := seededRoles(ctx, t)
		d.mu.Lock()
		d.roleRace = 1
		d.mu.Unlock()
		if err := a.UpdateAssumeRolePolicy(ctx, account314, "ops", lifecycleTrust2,
			backendtest.Grant(ctx, t, opsRoleARN)); err != nil {
			t.Fatal(err)
		}
		if got := d.role("ops").trust; got != lifecycleTrust2 {
			t.Errorf("trust %s", got)
		}
		sent := d.sent("UpdateRole")
		if len(sent) != 2 {
			t.Fatalf("sent %d UpdateRole, want 2", len(sent))
		}
		first, second := sent[0].(*iamv1.UpdateRoleRequest), sent[1].(*iamv1.UpdateRoleRequest)
		if first.GetRole().GetEtag() != "1" || second.GetRole().GetEtag() != "2" {
			t.Errorf("etags %q then %q, want 1 then 2", first.GetRole().GetEtag(), second.GetRole().GetEtag())
		}
		if first.GetRequestId() == second.GetRequestId() {
			t.Error("a new attempt reused the request id of the lost one")
		}
		if p := second.GetUpdateMask().GetPaths(); len(p) != 1 || p[0] != "spec.assume_role_policy" {
			t.Errorf("mask %v", p)
		}
	})
	t.Run("every attempt lost", func(t *testing.T) {
		a, d := seededRoles(ctx, t)
		d.mu.Lock()
		d.roleRace = TrustPolicyAttempts
		d.mu.Unlock()
		err := a.UpdateAssumeRolePolicy(ctx, account314, "ops", lifecycleTrust2, backendtest.Grant(ctx, t, opsRoleARN))
		if !iam.IsChanged(err) {
			t.Fatalf("err %v, want ConcurrentModification", err)
		}
		if got := d.role("ops").trust; got != lifecycleTrust {
			t.Errorf("trust changed to %s", got)
		}
		if n := len(d.sent("UpdateRole")); n != TrustPolicyAttempts {
			t.Errorf("sent %d UpdateRole, want %d", n, TrustPolicyAttempts)
		}
	})
	t.Run("reply lost", func(t *testing.T) {
		a, d := seededRoles(ctx, t)
		d.mu.Lock()
		d.failAfter["UpdateRole"] = 1
		d.mu.Unlock()
		if err := a.UpdateAssumeRolePolicy(ctx, account314, "ops", lifecycleTrust2,
			backendtest.Grant(ctx, t, opsRoleARN)); err != nil {
			t.Fatal(err)
		}
		if r := d.role("ops"); r.trust != lifecycleTrust2 || r.version != 2 {
			t.Errorf("role %+v, want one write", r)
		}
	})
}

func TestRoleDeleteSendsTheReadEtag(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	d.mu.Lock()
	d.roleRace = 1
	d.mu.Unlock()
	err := a.DeleteRole(ctx, account314, "ops", backendtest.Grant(ctx, t, opsRoleARN))
	if !iam.IsChanged(err) {
		t.Fatalf("DeleteRole after a change: %v, want ConcurrentModification", err)
	}
	if d.role("ops") == nil {
		t.Fatal("a role changed since the read was deleted")
	}
	if e := d.sent("DeleteRole")[0].(*iamv1.DeleteRoleRequest).GetEtag(); e != "1" {
		t.Errorf("DeleteRole etag %q, want 1", e)
	}
}

func TestRoleDeleteConflict(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	d.mu.Lock()
	d.roles[fold("projects/123456789012/roles/ops")].attached = []string{"P1"}
	d.mu.Unlock()
	err := a.DeleteRole(ctx, account314, "ops", backendtest.Grant(ctx, t, opsRoleARN))
	if resource.CodeOf(err) != resource.CodeConflict || resource.AsError(err).Field == "UnmodifiableEntity" {
		t.Fatalf("DeleteRole with a policy: %v, want DeleteConflict", err)
	}
}

func TestServiceLinkedRoleIsUnmodifiable(t *testing.T) {
	ctx := t.Context()
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	d.mu.Lock()
	d.roles[fold("projects/123456789012/roles/slr")] = &dirEntity{
		name: "projects/123456789012/roles/slr", path: iam.ServiceLinkedRolePath + "compute.vws/",
		id: "AROA00000000000000001", created: time.Now(), version: 1, trust: lifecycleTrust,
	}
	d.mu.Unlock()
	want := backendtest.Grant(ctx, t, "arn:vws:iam::123456789012:role"+iam.ServiceLinkedRolePath+"compute.vws/slr")
	for op, err := range map[string]error{
		"DeleteRole":             a.DeleteRole(ctx, account314, "slr", want),
		"UpdateAssumeRolePolicy": a.UpdateAssumeRolePolicy(ctx, account314, "slr", lifecycleTrust2, want),
	} {
		if f := resource.AsError(err).Field; f != "UnmodifiableEntity" {
			t.Errorf("%s: %v, want UnmodifiableEntity", op, err)
		}
	}
	if n, m := len(d.sent("DeleteRole")), len(d.sent("UpdateRole")); n != 0 || m != 0 {
		t.Errorf("sent %d DeleteRole and %d UpdateRole to a service-linked role", n, m)
	}
}

func TestRoleWritesRefuseTheZeroGrant(t *testing.T) {
	ctx := t.Context()
	a, d := seededRoles(ctx, t)
	reads := len(d.sent("GetRole"))
	if err := a.DeleteRole(ctx, account314, "ops", iam.AuthorizedPrincipal{}); err == nil {
		t.Error("DeleteRole accepted the zero grant")
	}
	if err := a.UpdateAssumeRolePolicy(ctx, account314, "ops", lifecycleTrust2,
		iam.AuthorizedPrincipal{}); err == nil {
		t.Error("UpdateAssumeRolePolicy accepted the zero grant")
	}
	if n := len(d.sent("GetRole")) - reads; n != 0 {
		t.Errorf("sent %d GetRole for the zero grant", n)
	}
}
