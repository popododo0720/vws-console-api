package backendtest

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMAdminHarness builds a fresh, empty iam.Admin for one IAMUsersAndGroups
// row.
type IAMAdminHarness func(t *testing.T) iam.Admin

// IAMUsersAndGroups runs the #314 contract of the iam.Admin user and group
// calls, which the in-memory fake and the vws-iam client must answer alike.
// Each row starts from an account with the users alice (/ops/) and bob
// (/eng/) and the group devs (/team/) with alice in it, set up through the
// same Admin. Messages are the AWS ones the Query surface sends.
func IAMUsersAndGroups(t *testing.T, newAdmin IAMAdminHarness) {
	t.Helper()
	for _, row := range iamUserGroupRows() {
		t.Run(row.name, func(t *testing.T) {
			ctx := context.Background()
			a := newAdmin(t)
			seedIAM(ctx, t, a)
			row.run(ctx, t, a)
		})
	}
}

// iamAccount is the account the rows work in; iamOther holds nothing.
func iamAccount() resource.AccountID { return mustAccount("123456789012") }

func iamOther() resource.AccountID { return mustAccount("210987654321") }

func mustAccount(s string) resource.AccountID {
	a, err := resource.Parse[resource.AccountID](s)
	if err != nil {
		panic(err)
	}
	return a
}

func seedIAM(ctx context.Context, t *testing.T, a iam.Admin) {
	t.Helper()
	for _, u := range [][2]string{{"alice", "/ops/"}, {"bob", "/eng/"}} {
		if _, err := a.CreateUser(ctx, iamAccount(), u[0], u[1]); err != nil {
			t.Fatalf("seed CreateUser %s: %v", u[0], err)
		}
	}
	if _, err := a.CreateGroup(ctx, iamAccount(), "devs", "/team/"); err != nil {
		t.Fatalf("seed CreateGroup: %v", err)
	}
	if err := a.AddUserToGroup(
		ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs"),
	); err != nil {
		t.Fatalf("seed AddUserToGroup: %v", err)
	}
}

// wantErr fails unless err has code and, when msg is set, that message.
func wantErr(t *testing.T, what string, err error, code resource.Code, msg string) {
	t.Helper()
	if got := resource.CodeOf(err); got != code {
		t.Fatalf("%s: code %v, want %v (%v)", what, got, code, err)
	}
	if msg != "" && resource.AsError(err).Message != msg {
		t.Fatalf("%s: message %q, want %q", what, resource.AsError(err).Message, msg)
	}
}

func wantOK(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func userNames(us []iam.User) []string {
	out := []string{}
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

func groupNames(gs []iam.Group) []string {
	out := []string{}
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

func wantNames(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s: %q, want %q", what, got, want)
	}
}

func members(ctx context.Context, t *testing.T, a iam.Admin, group string) []string {
	t.Helper()
	_, us, err := a.GetGroup(ctx, iamAccount(), group)
	wantOK(t, "GetGroup "+group, err)
	return userNames(us)
}

const arnPrefix = "arn:vws:iam::123456789012:"

type iamRow struct {
	name string
	run  func(ctx context.Context, t *testing.T, a iam.Admin)
}

// iamUserGroupRows are the #314 bundle 1 rows.
func iamUserGroupRows() []iamRow {
	return []iamRow{
		{"CreateUser returns the AWS user", func(ctx context.Context, t *testing.T, a iam.Admin) {
			u, err := a.CreateUser(ctx, iamAccount(), "carol", "/qa/")
			wantOK(t, "CreateUser", err)
			if u.Name != "carol" || u.Path != "/qa/" || u.ARN != arnPrefix+"user/qa/carol" ||
				!strings.HasPrefix(u.ID, "AIDA") || u.Created.IsZero() {
				t.Fatalf("CreateUser: %+v", u)
			}
			got, err := a.GetUser(ctx, iamAccount(), "carol")
			wantOK(t, "GetUser", err)
			if got.ARN != u.ARN || got.ID != u.ID || got.Path != "/qa/" {
				t.Fatalf("GetUser: %+v, created %+v", got, u)
			}
		}},
		{"CreateUser defaults the path to /", func(ctx context.Context, t *testing.T, a iam.Admin) {
			u, err := a.CreateUser(ctx, iamAccount(), "dave", "")
			wantOK(t, "CreateUser", err)
			if u.Path != "/" || u.ARN != arnPrefix+"user/dave" {
				t.Fatalf("CreateUser: %+v", u)
			}
		}},
		{"CreateUser of an existing name is EntityAlreadyExists", func(ctx context.Context, t *testing.T, a iam.Admin) {
			_, err := a.CreateUser(ctx, iamAccount(), "alice", "/")
			wantErr(t, "CreateUser", err, resource.CodeAlreadyExists, "User with name alice already exists.")
		}},
		{"CreateUser validates the name and the path", func(ctx context.Context, t *testing.T, a iam.Admin) {
			for _, name := range []string{"bad name", "root", strings.Repeat("a", 65), "a/b", ""} {
				_, err := a.CreateUser(ctx, iamAccount(), name, "/")
				wantErr(t, "CreateUser "+name, err, resource.CodeInvalidArgument, "")
			}
			for _, path := range []string{"ops", "/ops", "/" + strings.Repeat("a", 511) + "/"} {
				_, err := a.CreateUser(ctx, iamAccount(), "carol", path)
				wantErr(t, "CreateUser path "+path, err, resource.CodeInvalidArgument, "")
			}
			_, err := a.GetUser(ctx, iamAccount(), "carol")
			wantErr(t, "GetUser after the rejects", err, resource.CodeNotFound, "")
		}},
		{"GetUser of a missing user is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Admin) {
			_, err := a.GetUser(ctx, iamAccount(), "ghost")
			wantErr(t, "GetUser", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
		}},
		{"ListUsers is sorted by name and filtered by path prefix", func(ctx context.Context, t *testing.T, a iam.Admin) {
			us, err := a.ListUsers(ctx, iamAccount(), "")
			wantOK(t, "ListUsers", err)
			wantNames(t, "ListUsers", userNames(us), []string{"alice", "bob"})
			us, err = a.ListUsers(ctx, iamAccount(), "/ops/")
			wantOK(t, "ListUsers /ops/", err)
			wantNames(t, "ListUsers /ops/", userNames(us), []string{"alice"})
			if us[0].ARN != arnPrefix+"user/ops/alice" || us[0].Path != "/ops/" {
				t.Fatalf("ListUsers row: %+v", us[0])
			}
			us, err = a.ListUsers(ctx, iamAccount(), "/nobody/")
			wantOK(t, "ListUsers /nobody/", err)
			if us == nil || len(us) != 0 {
				t.Fatalf("ListUsers /nobody/: %#v", us)
			}
		}},
		{"UpdateUser moves the user to a new path", func(ctx context.Context, t *testing.T, a iam.Admin) {
			before, err := a.GetUser(ctx, iamAccount(), "alice")
			wantOK(t, "GetUser", err)
			wantOK(t, "UpdateUser", a.UpdateUser(ctx, iamAccount(), "alice", "/sre/", "", Grant(ctx, t, before.ARN)))
			u, err := a.GetUser(ctx, iamAccount(), "alice")
			wantOK(t, "GetUser", err)
			if u.Path != "/sre/" || u.ARN != arnPrefix+"user/sre/alice" || u.ID != before.ID {
				t.Fatalf("after UpdateUser: %+v, before %+v", u, before)
			}
			wantNames(t, "devs members", members(ctx, t, a, "devs"), []string{"alice"})
		}},
		{"UpdateUser to the current path or with nothing to change succeeds", func(
			ctx context.Context, t *testing.T, a iam.Admin,
		) {
			wantOK(
				t,
				"UpdateUser same path",
				a.UpdateUser(ctx, iamAccount(), "alice", "/ops/", "", UserGrant(ctx, t, a, iamAccount(), "alice")),
			)
			wantOK(
				t,
				"UpdateUser same name",
				a.UpdateUser(ctx, iamAccount(), "alice", "", "alice", UserGrant(ctx, t, a, iamAccount(), "alice")),
			)
		}},
		{"UpdateUser with a stale ARN is a conflict and changes nothing", func(
			ctx context.Context, t *testing.T, a iam.Admin,
		) {
			err := a.UpdateUser(ctx, iamAccount(), "alice", "/sre/", "", Grant(ctx, t, arnPrefix+"user/alice"))
			wantErr(t, "UpdateUser", err, resource.CodeConflict, iam.UserChanged)
			u, err := a.GetUser(ctx, iamAccount(), "alice")
			wantOK(t, "GetUser", err)
			if u.Path != "/ops/" {
				t.Fatalf("path moved: %+v", u)
			}
		}},
		{"UpdateUser validates the new path and finds the user", func(ctx context.Context, t *testing.T, a iam.Admin) {
			err := a.UpdateUser(ctx, iamAccount(), "alice", "sre", "", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantErr(t, "UpdateUser bad path", err, resource.CodeInvalidArgument, "")
			err = a.UpdateUser(ctx, iamAccount(), "ghost", "/sre/", "", UserGrant(ctx, t, a, iamAccount(), "ghost"))
			wantErr(t, "UpdateUser ghost", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
		}},
		{"DeleteUser of a group member is DeleteConflict", func(ctx context.Context, t *testing.T, a iam.Admin) {
			err := a.DeleteUser(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantErr(t, "DeleteUser", err, resource.CodeConflict, iam.UserDeleteConflict)
			_, err = a.GetUser(ctx, iamAccount(), "alice")
			wantOK(t, "GetUser after the conflict", err)
		}},
		{"DeleteUser deletes, and a second delete is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Admin) {
			wantOK(t, "DeleteUser", a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")))
			_, err := a.GetUser(ctx, iamAccount(), "bob")
			wantErr(t, "GetUser", err, resource.CodeNotFound, "")
			err = a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantErr(t, "DeleteUser again", err, resource.CodeNotFound, "The user with name bob cannot be found.")
			us, err := a.ListUsers(ctx, iamAccount(), "")
			wantOK(t, "ListUsers", err)
			wantNames(t, "ListUsers", userNames(us), []string{"alice"})
		}},
		{"CreateGroup returns the AWS group", func(ctx context.Context, t *testing.T, a iam.Admin) {
			g, err := a.CreateGroup(ctx, iamAccount(), "ops", "/x/")
			wantOK(t, "CreateGroup", err)
			if g.Name != "ops" || g.Path != "/x/" || g.ARN != arnPrefix+"group/x/ops" ||
				!strings.HasPrefix(g.ID, "AGPA") || g.Created.IsZero() {
				t.Fatalf("CreateGroup: %+v", g)
			}
			got, us, err := a.GetGroup(ctx, iamAccount(), "ops")
			wantOK(t, "GetGroup", err)
			if got.ARN != g.ARN || got.ID != g.ID || len(us) != 0 {
				t.Fatalf("GetGroup: %+v %+v", got, us)
			}
			g, err = a.CreateGroup(ctx, iamAccount(), "root", "")
			wantOK(t, "CreateGroup root", err)
			if g.Path != "/" || g.ARN != arnPrefix+"group/root" {
				t.Fatalf("CreateGroup root: %+v", g)
			}
		}},
		{"CreateGroup of an existing name is EntityAlreadyExists", func(ctx context.Context, t *testing.T, a iam.Admin) {
			_, err := a.CreateGroup(ctx, iamAccount(), "devs", "/")
			wantErr(t, "CreateGroup", err, resource.CodeAlreadyExists, "Group with name devs already exists.")
		}},
		{"CreateGroup validates the name and the path", func(ctx context.Context, t *testing.T, a iam.Admin) {
			for _, name := range []string{"bad name", strings.Repeat("g", 129), "a/b", ""} {
				_, err := a.CreateGroup(ctx, iamAccount(), name, "/")
				wantErr(t, "CreateGroup "+name, err, resource.CodeInvalidArgument, "")
			}
			_, err := a.CreateGroup(ctx, iamAccount(), "ops", "x")
			wantErr(t, "CreateGroup path", err, resource.CodeInvalidArgument, "")
		}},
		{"GetGroup lists the members; a missing group is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Admin) {
			g, us, err := a.GetGroup(ctx, iamAccount(), "devs")
			wantOK(t, "GetGroup", err)
			if g.ARN != arnPrefix+"group/team/devs" || len(us) != 1 || us[0].ARN != arnPrefix+"user/ops/alice" {
				t.Fatalf("GetGroup: %+v %+v", g, us)
			}
			_, _, err = a.GetGroup(ctx, iamAccount(), "ghost")
			wantErr(t, "GetGroup ghost", err, resource.CodeNotFound, "The group with name ghost cannot be found.")
		}},
		{"ListGroups is sorted by name and filtered by path prefix", func(ctx context.Context, t *testing.T, a iam.Admin) {
			_, err := a.CreateGroup(ctx, iamAccount(), "admins", "/ops/")
			wantOK(t, "CreateGroup", err)
			gs, err := a.ListGroups(ctx, iamAccount(), "")
			wantOK(t, "ListGroups", err)
			wantNames(t, "ListGroups", groupNames(gs), []string{"admins", "devs"})
			gs, err = a.ListGroups(ctx, iamAccount(), "/team/")
			wantOK(t, "ListGroups /team/", err)
			wantNames(t, "ListGroups /team/", groupNames(gs), []string{"devs"})
			if gs[0].ARN != arnPrefix+"group/team/devs" {
				t.Fatalf("ListGroups row: %+v", gs[0])
			}
		}},
		{"UpdateGroup moves the group to a new path", func(ctx context.Context, t *testing.T, a iam.Admin) {
			wantOK(
				t,
				"UpdateGroup",
				a.UpdateGroup(ctx, iamAccount(), "devs", "/eng/", "", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			g, us, err := a.GetGroup(ctx, iamAccount(), "devs")
			wantOK(t, "GetGroup", err)
			if g.Path != "/eng/" || g.ARN != arnPrefix+"group/eng/devs" || len(us) != 1 {
				t.Fatalf("after UpdateGroup: %+v %+v", g, us)
			}
			wantOK(
				t,
				"UpdateGroup same path",
				a.UpdateGroup(ctx, iamAccount(), "devs", "/eng/", "", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
		}},
		{"UpdateGroup validates the new path and finds the group", func(ctx context.Context, t *testing.T, a iam.Admin) {
			err := a.UpdateGroup(ctx, iamAccount(), "devs", "eng", "", GroupGrant(ctx, t, a, iamAccount(), "devs"))
			wantErr(t, "UpdateGroup bad path", err, resource.CodeInvalidArgument, "")
			wantErr(t, "UpdateGroup ghost", a.UpdateGroup(
				ctx, iamAccount(), "ghost", "/eng/", "", GroupGrant(ctx, t, a, iamAccount(), "ghost"),
			),
				resource.CodeNotFound, "The group with name ghost cannot be found.")
		}},
		{"AddUserToGroup adds a member and adding it again is a no-op", func(ctx context.Context, t *testing.T, a iam.Admin) {
			wantOK(
				t,
				"AddUserToGroup",
				a.AddUserToGroup(ctx, iamAccount(), "devs", "bob", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			wantNames(t, "members", members(ctx, t, a, "devs"), []string{"alice", "bob"})
			wantOK(
				t,
				"AddUserToGroup again",
				a.AddUserToGroup(ctx, iamAccount(), "devs", "bob", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			wantNames(t, "members", members(ctx, t, a, "devs"), []string{"alice", "bob"})
			gs, err := a.ListGroupsForUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "ListGroupsForUser", err)
			wantNames(t, "ListGroupsForUser", groupNames(gs), []string{"devs"})
			if gs[0].ARN != arnPrefix+"group/team/devs" {
				t.Fatalf("ListGroupsForUser row: %+v", gs[0])
			}
		}},
		{"AddUserToGroup of a missing group or user is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Admin) {
			wantErr(t, "missing group", a.AddUserToGroup(
				ctx, iamAccount(), "ghost", "bob", GroupGrant(ctx, t, a, iamAccount(), "ghost"),
			),
				resource.CodeNotFound, "The group with name ghost cannot be found.")
			wantErr(t, "missing user", a.AddUserToGroup(
				ctx, iamAccount(), "devs", "ghost", GroupGrant(ctx, t, a, iamAccount(), "devs"),
			),
				resource.CodeNotFound, "The user with name ghost cannot be found.")
			wantNames(t, "members", members(ctx, t, a, "devs"), []string{"alice"})
		}},
		{"AddUserToGroup past GroupsPerUser is LimitExceeded", func(ctx context.Context, t *testing.T, a iam.Admin) {
			for i := range iam.MaxGroupsPerUser {
				name := "g" + string(rune('a'+i))
				_, err := a.CreateGroup(ctx, iamAccount(), name, "/")
				wantOK(t, "CreateGroup "+name, err)
				if i < iam.MaxGroupsPerUser-1 {
					wantOK(
						t,
						"AddUserToGroup "+name,
						a.AddUserToGroup(ctx, iamAccount(), name, "alice", GroupGrant(ctx, t, a, iamAccount(), name)),
					)
				}
			}
			err := a.AddUserToGroup(
				ctx,
				iamAccount(),
				"g"+string(rune('a'+iam.MaxGroupsPerUser-1)),
				"alice",
				GroupGrant(ctx, t, a, iamAccount(), "g"+string(rune('a'+iam.MaxGroupsPerUser-1))),
			)
			wantErr(t, "AddUserToGroup past the quota", err, resource.CodeResourceExhausted,
				"Cannot exceed quota for GroupsPerUser: 10")
			wantOK(
				t,
				"AddUserToGroup to a group it is in",
				a.AddUserToGroup(ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			gs, err := a.ListGroupsForUser(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantOK(t, "ListGroupsForUser", err)
			if len(gs) != iam.MaxGroupsPerUser {
				t.Fatalf("%d groups: %q", len(gs), groupNames(gs))
			}
		}},
		{"RemoveUserFromGroup removes a member; a non-member is NoSuchEntity", func(
			ctx context.Context, t *testing.T, a iam.Admin,
		) {
			wantOK(
				t,
				"RemoveUserFromGroup",
				a.RemoveUserFromGroup(ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			wantNames(t, "members", members(ctx, t, a, "devs"), []string{})
			wantErr(t, "again", a.RemoveUserFromGroup(
				ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs"),
			),
				resource.CodeNotFound, "The user with name alice cannot be found.")
			wantErr(t, "never a member", a.RemoveUserFromGroup(
				ctx, iamAccount(), "devs", "bob", GroupGrant(ctx, t, a, iamAccount(), "devs"),
			),
				resource.CodeNotFound, "The user with name bob cannot be found.")
			wantErr(t, "missing group", a.RemoveUserFromGroup(
				ctx, iamAccount(), "ghost", "alice", GroupGrant(ctx, t, a, iamAccount(), "ghost"),
			),
				resource.CodeNotFound, "The group with name ghost cannot be found.")
			gs, err := a.ListGroupsForUser(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantOK(t, "ListGroupsForUser", err)
			wantNames(t, "ListGroupsForUser", groupNames(gs), []string{})
			wantOK(
				t,
				"DeleteUser once out of the group",
				a.DeleteUser(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice")),
			)
		}},
		{"DeleteGroup with members is DeleteConflict; an empty group deletes", func(
			ctx context.Context, t *testing.T, a iam.Admin,
		) {
			wantErr(t, "DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs")),
				resource.CodeConflict, iam.GroupDeleteConflict)
			wantOK(
				t,
				"RemoveUserFromGroup",
				a.RemoveUserFromGroup(ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			wantOK(t, "DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs")))
			_, _, err := a.GetGroup(ctx, iamAccount(), "devs")
			wantErr(t, "GetGroup", err, resource.CodeNotFound, "")
			wantErr(t, "DeleteGroup again", a.DeleteGroup(
				ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs"),
			),
				resource.CodeNotFound, "The group with name devs cannot be found.")
		}},
		{"ListGroupsForUser of a missing user is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Admin) {
			_, err := a.ListGroupsForUser(ctx, iamAccount(), "ghost", UserGrant(ctx, t, a, iamAccount(), "ghost"))
			wantErr(t, "ListGroupsForUser", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
			gs, err := a.ListGroupsForUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "ListGroupsForUser bob", err)
			wantNames(t, "ListGroupsForUser bob", groupNames(gs), []string{})
		}},
		{"changes bound to a stale ARN are ConcurrentModification and change nothing", func(
			ctx context.Context, t *testing.T, a iam.Admin,
		) {
			// #325 r1: the surface passes the ARN it authorized; an entity
			// that has moved since must not be changed.
			stale := arnPrefix + "group/old/devs"
			changed := func(what string, err error, msg string) {
				t.Helper()
				wantErr(t, what, err, resource.CodeConflict, msg)
				if !iam.IsChanged(err) {
					t.Fatalf("%s: %v is not a ConcurrentModification", what, err)
				}
			}
			changed("AddUserToGroup", a.AddUserToGroup(ctx, iamAccount(), "devs", "bob", Grant(ctx, t, stale)), iam.GroupChanged)
			changed("RemoveUserFromGroup", a.RemoveUserFromGroup(ctx, iamAccount(), "devs", "alice", Grant(ctx, t, stale)),
				iam.GroupChanged)
			wantNames(t, "members", members(ctx, t, a, "devs"), []string{"alice"})
			changed("UpdateGroup", a.UpdateGroup(ctx, iamAccount(), "devs", "/eng/", "", Grant(ctx, t, stale)), iam.GroupChanged)
			_, err := a.CreateGroup(ctx, iamAccount(), "empty", "/team/")
			wantOK(t, "CreateGroup empty", err)
			changed(
				"DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "empty", Grant(ctx, t, arnPrefix+"group/empty")), iam.GroupChanged,
			)
			changed("DeleteUser", a.DeleteUser(ctx, iamAccount(), "bob", Grant(ctx, t, arnPrefix+"user/bob")), iam.UserChanged)
			changed("UpdateUser", a.UpdateUser(ctx, iamAccount(), "bob", "/x/", "", Grant(ctx, t, arnPrefix+"user/bob")),
				iam.UserChanged)
			g, _, err := a.GetGroup(ctx, iamAccount(), "devs")
			wantOK(t, "GetGroup devs", err)
			if g.Path != "/team/" {
				t.Fatalf("UpdateGroup moved the group: %+v", g)
			}
			_, _, err = a.GetGroup(ctx, iamAccount(), "empty")
			wantOK(t, "the empty group stays", err)
			u, err := a.GetUser(ctx, iamAccount(), "bob")
			wantOK(t, "bob stays", err)
			if u.Path != "/eng/" {
				t.Fatalf("UpdateUser moved bob: %+v", u)
			}
			// The authorized ARN itself goes through.
			devs, empty, bob := arnPrefix+"group/team/devs", arnPrefix+"group/team/empty", arnPrefix+"user/eng/bob"
			wantOK(t, "AddUserToGroup", a.AddUserToGroup(ctx, iamAccount(), "devs", "bob", Grant(ctx, t, devs)))
			wantOK(t, "RemoveUserFromGroup", a.RemoveUserFromGroup(ctx, iamAccount(), "devs", "bob", Grant(ctx, t, devs)))
			wantOK(t, "UpdateGroup", a.UpdateGroup(ctx, iamAccount(), "devs", "/eng/", "", Grant(ctx, t, devs)))
			wantOK(t, "DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "empty", Grant(ctx, t, empty)))
			wantOK(t, "DeleteUser", a.DeleteUser(ctx, iamAccount(), "bob", Grant(ctx, t, bob)))
			// A missing entity is still NoSuchEntity, not a conflict.
			wantErr(t, "AddUserToGroup ghost", a.AddUserToGroup(ctx, iamAccount(), "ghost", "alice", Grant(ctx, t, stale)),
				resource.CodeNotFound, "The group with name ghost cannot be found.")
			wantErr(t, "DeleteUser ghost", a.DeleteUser(ctx, iamAccount(), "ghost", Grant(ctx, t, arnPrefix+"user/ghost")),
				resource.CodeNotFound, "The user with name ghost cannot be found.")
		}},
		{"another account sees none of it", func(ctx context.Context, t *testing.T, a iam.Admin) {
			us, err := a.ListUsers(ctx, iamOther(), "")
			wantOK(t, "ListUsers", err)
			wantNames(t, "ListUsers", userNames(us), []string{})
			gs, err := a.ListGroups(ctx, iamOther(), "")
			wantOK(t, "ListGroups", err)
			wantNames(t, "ListGroups", groupNames(gs), []string{})
			_, err = a.GetUser(ctx, iamOther(), "alice")
			wantErr(t, "GetUser", err, resource.CodeNotFound, "")
			wantErr(
				t,
				"DeleteUser",
				a.DeleteUser(ctx, iamOther(), "alice", UserGrant(ctx, t, a, iamOther(), "alice")),
				resource.CodeNotFound,
				"",
			)
			wantErr(
				t,
				"AddUserToGroup",
				a.AddUserToGroup(ctx, iamOther(), "devs", "bob", GroupGrant(ctx, t, a, iamOther(), "devs")),
				resource.CodeNotFound,
				"",
			)
			u, err := a.CreateUser(ctx, iamOther(), "alice", "/")
			wantOK(t, "CreateUser in the other account", err)
			if u.ARN != "arn:vws:iam::210987654321:user/alice" {
				t.Fatalf("CreateUser: %+v", u)
			}
			wantOK(
				t,
				"DeleteUser in the other account",
				a.DeleteUser(ctx, iamOther(), "alice", UserGrant(ctx, t, a, iamOther(), "alice")),
			)
			_, err = a.GetUser(ctx, iamAccount(), "alice")
			wantOK(t, "alice is still in the first account", err)
		}},
	}
}
