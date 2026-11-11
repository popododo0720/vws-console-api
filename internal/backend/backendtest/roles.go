package backendtest

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMRoles runs the #573 contract of the role lifecycle calls (CreateRole,
// ListRoles, UpdateAssumeRolePolicy, DeleteRole), which the in-memory fake
// and the vws-iam client must answer alike. Each row starts from an account
// with the role ops (/svc/) created through the same Directory. Messages are
// the AWS ones the Query surface sends.
func IAMRoles(t *testing.T, newAdmin IAMAdminHarness) {
	t.Helper()
	const opsARN = arnPrefix + "role/svc/ops"
	otherTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"storage.vws"},"Action":"sts:AssumeRole"}]}`
	rows := []struct {
		name string
		run  func(context.Context, *testing.T, iam.Directory)
	}{
		{"create answers the role", func(ctx context.Context, t *testing.T, a iam.Directory) {
			r, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{
				Name: "web", TrustPolicy: boundTrust, Description: "front", MaxSessionDuration: 7200,
			})
			wantOK(t, "CreateRole", err)
			if r.ARN != arnPrefix+"role/web" || r.Path != "/" || r.ID == "" || r.TrustPolicy != boundTrust ||
				r.Description != "front" || r.MaxSessionDuration != 7200 || r.Created.IsZero() {
				t.Fatalf("CreateRole: %+v", r)
			}
			got, err := a.GetRole(ctx, iamAccount(), "web", Grant(ctx, t, r.ARN))
			wantOK(t, "GetRole", err)
			if got.ARN != r.ARN || got.ID != r.ID || got.TrustPolicy != boundTrust {
				t.Fatalf("GetRole: %+v, want %+v", got, r)
			}
		}},
		{"create defaults the session to an hour", func(ctx context.Context, t *testing.T, a iam.Directory) {
			got, err := a.GetRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN))
			wantOK(t, "GetRole", err)
			if got.MaxSessionDuration != 3600 || got.Path != "/svc/" {
				t.Fatalf("GetRole: %+v", got)
			}
		}},
		{"duplicate name", func(ctx context.Context, t *testing.T, a iam.Directory) {
			_, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{Name: "ops", TrustPolicy: boundTrust})
			wantErr(t, "CreateRole", err, resource.CodeAlreadyExists, "Role with name ops already exists.")
		}},
		{"malformed trust policy", func(ctx context.Context, t *testing.T, a iam.Directory) {
			_, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{Name: "web", TrustPolicy: "{not json"})
			wantErr(t, "CreateRole", err, resource.CodeInvalidArgument, "Syntax errors in policy.")
			if f := resource.AsError(err).Field; f != "PolicyDocument" {
				t.Fatalf("CreateRole field %q, want PolicyDocument", f)
			}
			err = a.UpdateAssumeRolePolicy(ctx, iamAccount(), "ops", "{not json", Grant(ctx, t, opsARN))
			wantErr(t, "UpdateAssumeRolePolicy", err, resource.CodeInvalidArgument, "Syntax errors in policy.")
		}},
		{"bad input", func(ctx context.Context, t *testing.T, a iam.Directory) {
			for _, in := range []iam.RoleInput{
				{Name: "", TrustPolicy: boundTrust},
				{Name: "a/b", TrustPolicy: boundTrust},
				{Name: "web", Path: "svc", TrustPolicy: boundTrust},
				{Name: "web", TrustPolicy: boundTrust, MaxSessionDuration: 60},
			} {
				_, err := a.CreateRole(ctx, iamAccount(), in)
				wantErr(t, "CreateRole "+in.Name+in.Path, err, resource.CodeInvalidArgument, "")
			}
		}},
		{"bad role name on a write", func(ctx context.Context, t *testing.T, a iam.Directory) {
			for _, name := range []string{"", "a/b", strings.Repeat("r", 65)} {
				wantErr(t, "UpdateAssumeRolePolicy "+name,
					a.UpdateAssumeRolePolicy(ctx, iamAccount(), name, otherTrust, Grant(ctx, t, opsARN)),
					resource.CodeInvalidArgument, "")
				wantErr(t, "DeleteRole "+name, a.DeleteRole(ctx, iamAccount(), name, Grant(ctx, t, opsARN)),
					resource.CodeInvalidArgument, "")
			}
		}},
		{"list filters by path prefix", func(ctx context.Context, t *testing.T, a iam.Directory) {
			_, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{Name: "web", Path: "/front/", TrustPolicy: boundTrust})
			wantOK(t, "CreateRole", err)
			for prefix, want := range map[string][]string{
				"": {"ops", "web"}, "/svc/": {"ops"}, "/front/": {"web"}, "/none/": {},
			} {
				rs, err := a.ListRoles(ctx, iamAccount(), prefix)
				wantOK(t, "ListRoles "+prefix, err)
				wantNames(t, "ListRoles "+prefix, roleNames(rs), want)
			}
			rs, err := a.ListRoles(ctx, iamOther(), "")
			wantOK(t, "ListRoles other", err)
			wantNames(t, "ListRoles other", roleNames(rs), []string{})
		}},
		{"update trust policy", func(ctx context.Context, t *testing.T, a iam.Directory) {
			wantOK(t, "UpdateAssumeRolePolicy",
				a.UpdateAssumeRolePolicy(ctx, iamAccount(), "ops", otherTrust, Grant(ctx, t, opsARN)))
			got, err := a.GetRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN))
			wantOK(t, "GetRole", err)
			if got.TrustPolicy != otherTrust || got.Path != "/svc/" || got.MaxSessionDuration != 3600 {
				t.Fatalf("GetRole after update: %+v", got)
			}
		}},
		{"missing role", func(ctx context.Context, t *testing.T, a iam.Directory) {
			const msg = "The role with name ghost cannot be found."
			ghost := Grant(ctx, t, arnPrefix+"role/ghost")
			wantErr(t, "UpdateAssumeRolePolicy",
				a.UpdateAssumeRolePolicy(ctx, iamAccount(), "ghost", boundTrust, ghost), resource.CodeNotFound, msg)
			wantErr(t, "DeleteRole", a.DeleteRole(ctx, iamAccount(), "ghost", ghost), resource.CodeNotFound, msg)
		}},
		{"delete", func(ctx context.Context, t *testing.T, a iam.Directory) {
			wantOK(t, "DeleteRole", a.DeleteRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN)))
			_, err := a.GetRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN))
			wantErr(t, "GetRole after delete", err, resource.CodeNotFound, "The role with name ops cannot be found.")
			rs, err := a.ListRoles(ctx, iamAccount(), "")
			wantOK(t, "ListRoles", err)
			wantNames(t, "ListRoles after delete", roleNames(rs), []string{})
		}},
		{"delete then create again", func(ctx context.Context, t *testing.T, a iam.Directory) {
			wantOK(t, "DeleteRole", a.DeleteRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN)))
			_, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{Name: "ops", Path: "/other/", TrustPolicy: boundTrust})
			wantOK(t, "CreateRole again", err)
			// The grant was for /svc/ops: the role at /other/ is another one.
			wantErr(t, "DeleteRole stale grant", a.DeleteRole(ctx, iamAccount(), "ops", Grant(ctx, t, opsARN)),
				resource.CodeOf(iam.Changed(iam.RoleChanged)), "")
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ctx := context.Background()
			a := newAdmin(t)
			if _, err := a.CreateRole(ctx, iamAccount(), iam.RoleInput{
				Name: "ops", Path: "/svc/", TrustPolicy: boundTrust,
			}); err != nil {
				t.Fatalf("seed CreateRole: %v", err)
			}
			row.run(ctx, t, a)
		})
	}
}

func roleNames(rs []iam.Role) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
