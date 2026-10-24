package backendtest

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMResolver runs the iam.Resolver contract (#358), which the in-memory fake
// and the vws-iam client must answer alike:
//   - each Resolve call answers the entity's ARN, path included, and its
//     unique ID, as CreateUser, CreateGroup and CreateRole returned them;
//   - a missing entity is NotFound with the AWS NoSuchEntity message;
//   - ResolveGroup reads the group only: an IAMCallCounter sends one request,
//     never one per member.
//
// Roles are checked when serves has ServesRoles.
func IAMResolver(t *testing.T, newDir IAMAdminHarness, serves IAMServes) {
	t.Helper()
	acct := iamAccount()
	seed := func(ctx context.Context, t *testing.T) (iam.Directory, map[string]iam.Ref) {
		t.Helper()
		d := newDir(t)
		want := map[string]iam.Ref{}
		for _, u := range [][2]string{{"alice", "/ops/"}, {"bob", "/eng/"}} {
			got, err := d.CreateUser(ctx, acct, u[0], u[1])
			wantOK(t, "seed CreateUser "+u[0], err)
			want["user "+u[0]] = iam.Ref{ARN: got.ARN, ID: got.ID}
		}
		g, err := d.CreateGroup(ctx, acct, "devs", "/team/")
		wantOK(t, "seed CreateGroup", err)
		want["group devs"] = iam.Ref{ARN: g.ARN, ID: g.ID}
		for _, m := range []string{"alice", "bob"} {
			wantOK(t, "seed AddUserToGroup "+m, d.AddUserToGroup(ctx, acct, "devs", m, Grant(ctx, t, g.ARN)))
		}
		if serves&ServesRoles != 0 {
			r, err := d.CreateRole(ctx, acct, iam.RoleInput{Name: "ops", Path: "/svc/", TrustPolicy: boundTrust})
			wantOK(t, "seed CreateRole", err)
			want["role ops"] = iam.Ref{ARN: r.ARN, ID: r.ID}
		}
		return d, want
	}
	check := func(t *testing.T, what string, got iam.Ref, err error, want iam.Ref, path string) {
		t.Helper()
		wantOK(t, what, err)
		if got != want || got.ID == "" {
			t.Fatalf("%s = %+v, want %+v", what, got, want)
		}
		if !strings.Contains(got.ARN, path) {
			t.Fatalf("%s ARN %s has no path %s", what, got.ARN, path)
		}
	}
	t.Run("user", func(t *testing.T) {
		ctx := context.Background()
		d, want := seed(ctx, t)
		got, err := d.ResolveUser(ctx, acct, "alice")
		check(t, "ResolveUser alice", got, err, want["user alice"], "/ops/")
		got, err = d.ResolveUser(ctx, acct, "ghost")
		wantErr(t, "ResolveUser ghost", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
		if got != (iam.Ref{}) {
			t.Fatalf("ResolveUser ghost answered %+v", got)
		}
	})
	t.Run("group", func(t *testing.T) {
		ctx := context.Background()
		d, want := seed(ctx, t)
		counter, counts := d.(IAMCallCounter)
		sent := 0
		if counts {
			sent = counter.Calls()
		}
		got, err := d.ResolveGroup(ctx, acct, "devs")
		check(t, "ResolveGroup devs", got, err, want["group devs"], "/team/")
		if counts && counter.Calls()-sent != 1 {
			t.Fatalf("ResolveGroup sent %d requests, want 1 (no member reads)", counter.Calls()-sent)
		}
		got, err = d.ResolveGroup(ctx, acct, "ghost")
		wantErr(t, "ResolveGroup ghost", err, resource.CodeNotFound, "The group with name ghost cannot be found.")
		if got != (iam.Ref{}) {
			t.Fatalf("ResolveGroup ghost answered %+v", got)
		}
	})
	if serves&ServesRoles == 0 {
		return
	}
	t.Run("role", func(t *testing.T) {
		ctx := context.Background()
		d, want := seed(ctx, t)
		got, err := d.ResolveRole(ctx, acct, "ops")
		check(t, "ResolveRole ops", got, err, want["role ops"], "/svc/")
		got, err = d.ResolveRole(ctx, acct, "ghost")
		wantErr(t, "ResolveRole ghost", err, resource.CodeNotFound, "The role with name ghost cannot be found.")
		if got != (iam.Ref{}) {
			t.Fatalf("ResolveRole ghost answered %+v", got)
		}
	})
}
