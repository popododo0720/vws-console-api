package iamclient

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// movingAdmin moves one group or user to /denied/ right after the surface's
// first lookup of it. A concurrent UpdateGroup or UpdateUser does the same
// between the authorization and the change.
type movingAdmin struct {
	iam.Directory
	tb          testing.TB
	group, user string
	moved       bool
}

func (a *movingAdmin) ResolveGroup(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	g, err := a.Directory.ResolveGroup(ctx, account, name)
	if err == nil && !a.moved && name == a.group {
		a.moved = true
		if err := a.UpdateGroup(ctx, account, name, "/denied/", "", backendtest.Grant(ctx, a.tb, g.ARN)); err != nil {
			return iam.Ref{}, err
		}
	}
	return g, err
}

func (a *movingAdmin) ResolveUser(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	u, err := a.Directory.ResolveUser(ctx, account, name)
	if err == nil && !a.moved && name == a.user {
		a.moved = true
		if err := a.UpdateUser(ctx, account, name, "/denied/", "", backendtest.Grant(ctx, a.tb, u.ARN)); err != nil {
			return iam.Ref{}, err
		}
	}
	return u, err
}

// memberWrites counts the UpdateGroup requests on spec.members.
func memberWrites(d *directory) int {
	n := 0
	for _, m := range d.sent("UpdateGroup") {
		for _, p := range m.(*iamv1.UpdateGroupRequest).GetUpdateMask().GetPaths() {
			if p == "spec.members" {
				n++
			}
		}
	}
	return n
}

// #325 r1: over gRPC a group or user change acts only on the ARN the caller
// was authorized on. When the entity moves between the authorization and the
// write, or between two membership attempts, the answer is 409
// ConcurrentModification and nothing is written.
func TestGroupAndUserChangesActOnTheAuthorizedARNOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name        string
		form        url.Values
		group, user string // moved after the surface's lookup
		racePath    string // moved by the writer that wins attempt 1
		unchanged   func(t *testing.T, a iam.Directory, d *directory, writes int)
	}{
		{
			name: "AddUserToGroup", group: "devs",
			form:      url.Values{"Action": {"AddUserToGroup"}, "GroupName": {"devs"}, "UserName": {"bob"}},
			unchanged: membersStay,
		},
		{
			name: "AddUserToGroup moved on attempt 1", racePath: "/denied/",
			form:      url.Values{"Action": {"AddUserToGroup"}, "GroupName": {"devs"}, "UserName": {"bob"}},
			unchanged: membersStay,
		},
		{
			name: "RemoveUserFromGroup", group: "devs",
			form:      url.Values{"Action": {"RemoveUserFromGroup"}, "GroupName": {"devs"}, "UserName": {"alice"}},
			unchanged: membersStay,
		},
		{
			name: "RemoveUserFromGroup moved on attempt 1", racePath: "/denied/",
			form:      url.Values{"Action": {"RemoveUserFromGroup"}, "GroupName": {"devs"}, "UserName": {"alice"}},
			unchanged: membersStay,
		},
		{
			name: "DeleteGroup", group: "empty",
			form: url.Values{"Action": {"DeleteGroup"}, "GroupName": {"empty"}},
			unchanged: func(t *testing.T, a iam.Directory, _ *directory, _ int) {
				t.Helper()
				if _, _, err := a.GetGroup(
					t.Context(),
					account314,
					"empty",
					backendtest.GroupGrant(t.Context(), t, a, account314, "empty"),
				); err != nil {
					t.Errorf("the group was deleted: %v", err)
				}
			},
		},
		{
			name: "UpdateGroup", group: "devs",
			form: url.Values{"Action": {"UpdateGroup"}, "GroupName": {"devs"}, "NewPath": {"/x/"}},
			unchanged: func(t *testing.T, a iam.Directory, _ *directory, _ int) {
				t.Helper()
				if g, _, err := a.GetGroup(
					t.Context(),
					account314,
					"devs",
					backendtest.GroupGrant(t.Context(), t, a, account314, "devs"),
				); err != nil || g.Path != "/denied/" {
					t.Errorf("the group moved to %+v: %v", g, err)
				}
			},
		},
		{
			name: "DeleteUser", user: "erin",
			form: url.Values{"Action": {"DeleteUser"}, "UserName": {"erin"}},
			unchanged: func(t *testing.T, a iam.Directory, _ *directory, _ int) {
				t.Helper()
				if _, err := a.GetUser(
					t.Context(),
					account314,
					"erin",
					backendtest.UserGrant(t.Context(), t, a, account314, "erin"),
				); err != nil {
					t.Errorf("the user was deleted: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mover := &movingAdmin{tb: t, group: tc.group, user: tc.user}
			h, _, d := dirQueryHarnessWith(t, func(a iam.Directory) iam.Directory {
				mover.Directory = a
				return mover
			})
			ctx := t.Context()
			if _, err := mover.CreateGroup(ctx, account314, "empty", "/team/"); err != nil {
				t.Fatal(err)
			}
			if _, err := mover.CreateUser(ctx, account314, "erin", "/ops/"); err != nil {
				t.Fatal(err)
			}
			d.mu.Lock()
			if tc.racePath != "" {
				d.race, d.racePath = 1, tc.racePath
			}
			d.mu.Unlock()
			before := memberWrites(d)
			if tc.racePath != "" {
				before++ // attempt 1 is sent, and vws-iam refuses it on the etag
			}
			res := queryCall(t, h, tc.form)
			tc.unchanged(t, mover.Directory, d, memberWrites(d)-before)
			expect(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
		})
	}
}

// membersStay checks that devs still has only alice and that no member list
// reached vws-iam beyond an attempt vws-iam refused on the etag.
func membersStay(t *testing.T, a iam.Directory, _ *directory, writes int) {
	t.Helper()
	_, us, err := a.GetGroup(
		t.Context(),
		account314,
		"devs",
		backendtest.GroupGrant(t.Context(), t, a, account314, "devs"),
	)
	if err != nil || len(us) != 1 || us[0].Name != "alice" {
		t.Errorf("members %+v: %v", us, err)
	}
	if writes > 0 {
		t.Errorf("%d member writes reached vws-iam after the group moved", writes)
	}
}

// #325 r1: DeleteUser and DeleteGroup read the entity first and send that
// read's etag. An entity changed in between is a ConcurrentModification, not
// a DeleteConflict, and stays.
func TestDeletesCarryTheEtagTheyRead(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	if _, err := a.CreateGroup(ctx, account314, "empty", "/team/"); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.deleteRace = 2
	d.mu.Unlock()
	err := a.DeleteUser(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if !iam.IsChanged(err) || resource.AsError(err).Message != iam.UserChanged {
		t.Errorf("DeleteUser of a changed user: %v", err)
	}
	err = a.DeleteGroup(ctx, account314, "empty", backendtest.GroupGrant(ctx, t, a, account314, "empty"))
	if !iam.IsChanged(err) || resource.AsError(err).Message != iam.GroupChanged {
		t.Errorf("DeleteGroup of a changed group: %v", err)
	}
	if _, err := a.GetUser(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob")); err != nil {
		t.Errorf("bob was deleted: %v", err)
	}
	if _, _, err := a.GetGroup(
		ctx,
		account314,
		"empty",
		backendtest.GroupGrant(ctx, t, a, account314, "empty"),
	); err != nil {
		t.Errorf("empty was deleted: %v", err)
	}
	if err := a.DeleteUser(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob")); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteGroup(ctx, account314, "empty", backendtest.GroupGrant(ctx, t, a, account314, "empty")); err != nil {
		t.Fatal(err)
	}
	du := d.sent("DeleteUser")
	dg := d.sent("DeleteGroup")
	last := du[len(du)-1].(*iamv1.DeleteUserRequest)
	if last.GetName() != "projects/123456789012/users/bob" || last.GetEtag() == "" ||
		!uuidV4.MatchString(last.GetRequestId()) {
		t.Errorf("DeleteUser sent %v", last)
	}
	if g := dg[len(dg)-1].(*iamv1.DeleteGroupRequest); g.GetName() != "projects/123456789012/groups/empty" ||
		g.GetEtag() == "" {
		t.Errorf("DeleteGroup sent %v", g)
	}
	// A member still makes DeleteGroup a DeleteConflict.
	err = a.DeleteGroup(ctx, account314, "devs", backendtest.GroupGrant(ctx, t, a, account314, "devs"))
	if resource.CodeOf(err) != resource.CodeConflict || iam.IsChanged(err) ||
		resource.AsError(err).Message != iam.GroupDeleteConflict {
		t.Errorf("DeleteGroup with a member: %v", err)
	}
}
