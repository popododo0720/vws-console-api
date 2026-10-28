package backendtest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMServes names the iam.Directory call families a backend serves beyond users,
// groups and access keys. A family a backend does not serve is still checked
// for the zero AuthorizedPrincipal, which every bound call refuses before it reads
// anything.
type IAMServes uint

const (
	// ServesLoginProfiles is the login profile family.
	ServesLoginProfiles IAMServes = 1 << iota
	// ServesRoles is the role family.
	ServesRoles
	// ServesEntityPolicies is the attached and inline policy family.
	ServesEntityPolicies
	// ServesMFADevices is the MFA device family.
	ServesMFADevices

	// ServesAll is every family; the in-memory fake serves them all.
	ServesAll = ServesLoginProfiles | ServesRoles | ServesEntityPolicies | ServesMFADevices
)

// IAMCallCounter is an iam.Directory that counts the requests it sends to its
// backend. IAMAuthorizedPrincipal then also checks that a call with the zero
// AuthorizedPrincipal sends none.
type IAMCallCounter interface {
	iam.Directory
	Calls() int
}

// boundRow is one iam.Directory call bound to an AuthorizedPrincipal (#342).
type boundRow struct {
	op     string
	needs  IAMServes // zero: users, groups and access keys only
	arn    string    // the entity's ARN after the seed
	moved  string    // the same entity on another path: a stale binding
	msg    string    // the Changed message
	writes bool      // an authorized call changes the snapshot
	call   func(ctx context.Context, a iam.Directory, want iam.AuthorizedPrincipal) error
}

const (
	boundAlice = "arn:vws:iam::123456789012:user/ops/alice"
	boundBob   = "arn:vws:iam::123456789012:user/eng/bob"
	boundCarol = "arn:vws:iam::123456789012:user/eng/carol"
	boundDevs  = "arn:vws:iam::123456789012:group/team/devs"
	boundEmpty = "arn:vws:iam::123456789012:group/team/empty"
	boundOps   = "arn:vws:iam::123456789012:role/svc/ops"
	boundPw    = "correct horse battery 7"
	boundTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"compute.vws"},"Action":"sts:AssumeRole"}]}`
	boundDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
)

func boundPolicyARN(name string) string { return "arn:vws:iam::123456789012:policy/" + name }

// boundRows are the bound calls; key is bob's seeded access key id, set
// after the seed.
func boundRows(key *string) []boundRow {
	user := func(op, arn string, needs IAMServes, writes bool,
		call func(context.Context, iam.Directory, iam.AuthorizedPrincipal) error,
	) boundRow {
		return boundRow{op, needs, arn, strings.Replace(arn, ":user/", ":user/denied/", 1), iam.UserChanged, writes, call}
	}
	group := func(
		op, arn string, writes bool, call func(context.Context, iam.Directory, iam.AuthorizedPrincipal) error,
	) boundRow {
		return boundRow{op, 0, arn, strings.Replace(arn, ":group/", ":group/denied/", 1), iam.GroupChanged, writes, call}
	}
	role := func(
		op string, needs IAMServes, call func(context.Context, iam.Directory, iam.AuthorizedPrincipal) error,
	) boundRow {
		return boundRow{
			op, ServesRoles | needs, boundOps, strings.Replace(boundOps, ":role/", ":role/denied/", 1),
			iam.RoleChanged, true, call,
		}
	}
	acct := iamAccount()
	desc := "bound"
	return []boundRow{
		user("DeleteUser", boundCarol, 0, true, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.DeleteUser(ctx, acct, "carol", w)
		}),
		user("UpdateUser", boundBob, 0, true, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.UpdateUser(ctx, acct, "bob", "/moved/", "", w)
		}),
		user("CreateAccessKey", boundBob, 0, true, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			_, err := a.CreateAccessKey(ctx, acct, "bob", w)
			return err
		}),
		user("ListAccessKeys", boundBob, 0, false, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			ks, err := a.ListAccessKeys(ctx, acct, "bob", w)
			if err == nil && len(ks) != 1 {
				return fmt.Errorf("keys %v, want the seeded one", ks)
			}
			return err
		}),
		user("UpdateAccessKey", boundBob, 0, true, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			return a.UpdateAccessKey(ctx, acct, "bob", *key, iam.AccessKeyInactive, w)
		}),
		user("DeleteAccessKey", boundBob, 0, true, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			return a.DeleteAccessKey(ctx, acct, "bob", *key, w)
		}),
		user("ListGroupsForUser", boundAlice, 0, false, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			gs, err := a.ListGroupsForUser(ctx, acct, "alice", w)
			if err == nil && len(gs) != 1 {
				return fmt.Errorf("groups %v, want devs", gs)
			}
			return err
		}),
		user("GetUser", boundAlice, 0, false, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			u, err := a.GetUser(ctx, acct, "alice", w)
			if err != nil && u != (iam.User{}) {
				return fmt.Errorf("the error %q came with the user %+v", err.Error(), u)
			}
			if err == nil && (u.ARN != boundAlice || u.Name != "alice" || u.Path != "/ops/" || u.ID == "") {
				return fmt.Errorf("user %+v, want alice", u)
			}
			return err
		}),
		group("GetGroup", boundDevs, false, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			g, us, err := a.GetGroup(ctx, acct, "devs", w)
			if err != nil && (g != (iam.Group{}) || us != nil) {
				return fmt.Errorf("the error %q came with the group %+v and members %v", err.Error(), g, us)
			}
			if err == nil && (g.ARN != boundDevs || g.ID == "" || !slices.Equal(userNames(us), []string{"alice"})) {
				return fmt.Errorf("group %+v members %v, want devs with alice", g, userNames(us))
			}
			return err
		}),
		{
			"GetRole", ServesRoles, boundOps, strings.Replace(boundOps, ":role/", ":role/denied/", 1),
			iam.RoleChanged, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				r, err := a.GetRole(ctx, acct, "ops", w)
				if err != nil && r != (iam.Role{}) {
					return fmt.Errorf("the error %q came with the role %+v", err.Error(), r)
				}
				if err == nil && (r.ARN != boundOps || r.ID == "" || r.TrustPolicy != boundTrust) {
					return fmt.Errorf("role %+v, want ops", r)
				}
				return err
			},
		},
		group("UpdateGroup", boundDevs, true, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.UpdateGroup(ctx, acct, "devs", "/moved/", "", w)
		}),
		group("DeleteGroup", boundEmpty, true, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.DeleteGroup(ctx, acct, "empty", w)
		}),
		group("AddUserToGroup", boundDevs, true, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.AddUserToGroup(ctx, acct, "devs", "bob", w)
		}),
		group("RemoveUserFromGroup", boundDevs, true, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			return a.RemoveUserFromGroup(ctx, acct, "devs", "alice", w)
		}),
		user("CreateLoginProfile", boundBob, ServesLoginProfiles, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				_, err := a.CreateLoginProfile(ctx, acct, "bob", boundPw, w)
				return err
			}),
		user("GetLoginProfile", boundAlice, ServesLoginProfiles, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				_, err := a.GetLoginProfile(ctx, acct, "alice", w)
				return err
			}),
		user("UpdateLoginProfile", boundAlice, ServesLoginProfiles, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.UpdateLoginProfile(ctx, acct, "alice", boundPw+"x", w)
			}),
		user("DeleteLoginProfile", boundAlice, ServesLoginProfiles, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.DeleteLoginProfile(ctx, acct, "alice", w)
			}),
		user("ListMFADevices", boundAlice, ServesMFADevices, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				_, err := a.ListMFADevices(ctx, acct, "alice", "", 0, w)
				return err
			}),
		role("UpdateRole", 0, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.UpdateRole(ctx, acct, "ops", iam.RoleUpdate{Description: &desc}, w)
		}),
		role("UpdateRoleDescription", 0, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			_, err := a.UpdateRoleDescription(ctx, acct, "ops", desc, w)
			return err
		}),
		role("UpdateAssumeRolePolicy", 0, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.UpdateAssumeRolePolicy(ctx, acct, "ops", strings.Replace(boundTrust, "compute", "storage", 1), w)
		}),
		role("DeleteRole", 0, func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
			return a.DeleteRole(ctx, acct, "ops", w)
		}),
		user("AttachUserPolicy", boundAlice, ServesEntityPolicies, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.AttachPolicy(ctx, acct, iam.EntityUser, "alice", boundPolicyARN("P2"), w)
			}),
		user("DetachUserPolicy", boundAlice, ServesEntityPolicies, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.DetachPolicy(ctx, acct, iam.EntityUser, "alice", boundPolicyARN("P1"), w)
			}),
		user("ListAttachedUserPolicies", boundAlice, ServesEntityPolicies, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				ps, err := a.ListAttachedPolicies(ctx, acct, iam.EntityUser, "alice", w)
				if err == nil && len(ps) != 1 {
					return fmt.Errorf("attached %v, want P1", ps)
				}
				return err
			}),
		user("PutUserPolicy", boundAlice, ServesEntityPolicies, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.PutInlinePolicy(ctx, acct, iam.EntityUser, "alice", "inline2", boundDoc, w)
			}),
		user("GetUserPolicy", boundAlice, ServesEntityPolicies, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				doc, err := a.GetInlinePolicy(ctx, acct, iam.EntityUser, "alice", "inline", w)
				if err == nil && doc != boundDoc {
					return fmt.Errorf("document %q", doc)
				}
				return err
			}),
		user("DeleteUserPolicy", boundAlice, ServesEntityPolicies, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.DeleteInlinePolicy(ctx, acct, iam.EntityUser, "alice", "inline", w)
			}),
		user("ListUserPolicies", boundAlice, ServesEntityPolicies, false,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				names, err := a.ListInlinePolicies(ctx, acct, iam.EntityUser, "alice", w)
				if err == nil && !slices.Equal(names, []string{"inline"}) {
					return fmt.Errorf("inline policies %v", names)
				}
				return err
			}),
		{
			"AttachGroupPolicy", ServesEntityPolicies, boundDevs,
			strings.Replace(boundDevs, ":group/", ":group/denied/", 1), iam.GroupChanged, true,
			func(ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal) error {
				return a.AttachPolicy(ctx, acct, iam.EntityGroup, "devs", boundPolicyARN("P2"), w)
			},
		},
		role("AttachRolePolicy", ServesEntityPolicies, func(
			ctx context.Context, a iam.Directory, w iam.AuthorizedPrincipal,
		) error {
			return a.AttachPolicy(ctx, acct, iam.EntityRole, "ops", boundPolicyARN("P2"), w)
		}),
	}
}

// IAMAuthorizedPrincipal runs the #342 contract of every iam.Directory call bound to
// an AuthorizedPrincipal, which the in-memory fake and the vws-iam client must
// answer alike:
//   - the zero AuthorizedPrincipal is an internal error, and nothing is read or
//     written (an IAMCallCounter sends no request);
//   - a binding to the entity's ARN on another path (a user, group or role
//     that moved since the caller was authorized) is ConcurrentModification
//     with the entity's Changed message, and nothing is written;
//   - the binding iam.Authorize returned for the entity's current ARN is
//     served.
//
// Families outside serves get the zero row only.
func IAMAuthorizedPrincipal(t *testing.T, newAdmin IAMPolicyHarness, serves IAMServes) {
	t.Helper()
	var key string
	seed := func(ctx context.Context, t *testing.T, a iam.Directory, policy PolicySeeder) {
		t.Helper()
		seedBound(ctx, t, a, policy, serves)
		ks, err := a.ListAccessKeys(ctx, iamAccount(), "bob", Grant(ctx, t, boundBob))
		wantOK(t, "seed ListAccessKeys", err)
		key = ks[0].AccessKeyID
	}
	for _, row := range boundRows(&key) {
		served := row.needs&serves == row.needs
		t.Run(row.op+"/zero", func(t *testing.T) {
			ctx := context.Background()
			a, policy := newAdmin(t)
			seed(ctx, t, a, policy)
			before := boundSnapshot(ctx, t, a, serves)
			counter, counts := a.(IAMCallCounter)
			sent := 0
			if counts {
				sent = counter.Calls()
			}
			err := row.call(ctx, a, iam.AuthorizedPrincipal{})
			wantErr(t, row.op+" with the zero AuthorizedPrincipal", err, resource.CodeInternal, "")
			if counts && counter.Calls() != sent {
				t.Fatalf("%s with the zero AuthorizedPrincipal sent %d requests", row.op, counter.Calls()-sent)
			}
			if after := boundSnapshot(ctx, t, a, serves); after != before {
				t.Fatalf("%s with the zero AuthorizedPrincipal changed the state:\n%s\nwant\n%s", row.op, after, before)
			}
		})
		if !served {
			continue
		}
		t.Run(row.op+"/moved", func(t *testing.T) {
			ctx := context.Background()
			a, policy := newAdmin(t)
			seed(ctx, t, a, policy)
			before := boundSnapshot(ctx, t, a, serves)
			err := row.call(ctx, a, Grant(ctx, t, row.moved))
			wantErr(t, row.op+" bound to "+row.moved, err, resource.CodeConflict, row.msg)
			if !iam.IsChanged(err) {
				t.Fatalf("%s bound to %s: %v is not ConcurrentModification", row.op, row.moved, err)
			}
			if after := boundSnapshot(ctx, t, a, serves); after != before {
				t.Fatalf("%s bound to a moved entity changed the state:\n%s\nwant\n%s", row.op, after, before)
			}
		})
		t.Run(row.op+"/authorized", func(t *testing.T) {
			ctx := context.Background()
			a, policy := newAdmin(t)
			seed(ctx, t, a, policy)
			before := boundSnapshot(ctx, t, a, serves)
			wantOK(t, row.op+" bound to "+row.arn, row.call(ctx, a, Grant(ctx, t, row.arn)))
			if after := boundSnapshot(ctx, t, a, serves); row.writes && after == before {
				t.Fatalf("%s bound to %s changed nothing", row.op, row.arn)
			}
		})
	}
}

// seedBound is the IAMUsersAndGroups seed, the user carol (/eng/) with
// nothing, the empty group "empty" (/team/) and one access key of bob's, and for each family served: a console
// password for alice; the role ops (/svc/); the managed policies P1 and P2
// with P1 attached to alice and alice's inline policy "inline". A nil policy
// seeder creates the managed policies with CreatePolicy.
func seedBound(ctx context.Context, t *testing.T, a iam.Directory, policy PolicySeeder, serves IAMServes) {
	t.Helper()
	acct := iamAccount()
	seedIAM(ctx, t, a)
	if _, err := a.CreateUser(ctx, acct, "carol", "/eng/"); err != nil {
		t.Fatalf("seed CreateUser carol: %v", err)
	}
	if _, err := a.CreateGroup(ctx, acct, "empty", "/team/"); err != nil {
		t.Fatalf("seed CreateGroup empty: %v", err)
	}
	if _, err := a.CreateAccessKey(ctx, acct, "bob", Grant(ctx, t, boundBob)); err != nil {
		t.Fatalf("seed CreateAccessKey: %v", err)
	}
	if serves&ServesLoginProfiles != 0 {
		if _, err := a.CreateLoginProfile(ctx, acct, "alice", boundPw, Grant(ctx, t, boundAlice)); err != nil {
			t.Fatalf("seed CreateLoginProfile: %v", err)
		}
	}
	if serves&ServesRoles != 0 {
		in := iam.RoleInput{Name: "ops", Path: "/svc/", TrustPolicy: boundTrust, Description: "seed"}
		if _, err := a.CreateRole(ctx, acct, in); err != nil {
			t.Fatalf("seed CreateRole: %v", err)
		}
	}
	if serves&ServesEntityPolicies != 0 {
		for _, p := range []string{"P1", "P2"} {
			if policy != nil {
				policy(t, p, "/")
				continue
			}
			if _, err := a.CreatePolicy(ctx, acct, p, "/", boundDoc, ""); err != nil {
				t.Fatalf("seed CreatePolicy %s: %v", p, err)
			}
		}
		if err := a.AttachPolicy(
			ctx, acct, iam.EntityUser, "alice", boundPolicyARN("P1"), Grant(ctx, t, boundAlice),
		); err != nil {
			t.Fatalf("seed AttachPolicy: %v", err)
		}
		if err := a.PutInlinePolicy(
			ctx, acct, iam.EntityUser, "alice", "inline", boundDoc, Grant(ctx, t, boundAlice),
		); err != nil {
			t.Fatalf("seed PutInlinePolicy: %v", err)
		}
	}
}

// boundSnapshot renders every entity and attachment the bound calls can
// change, read with the bindings of their current ARNs.
func boundSnapshot(ctx context.Context, t *testing.T, a iam.Directory, serves IAMServes) string {
	t.Helper()
	acct := iamAccount()
	var b strings.Builder
	us, err := a.ListUsers(ctx, acct, "/")
	wantOK(t, "snapshot ListUsers", err)
	for _, u := range us {
		fmt.Fprintf(&b, "user %s\n", u.ARN)
		ks, err := a.ListAccessKeys(ctx, acct, u.Name, Grant(ctx, t, u.ARN))
		wantOK(t, "snapshot ListAccessKeys", err)
		for _, k := range ks {
			fmt.Fprintf(&b, "  key %s %s\n", k.AccessKeyID, k.Status)
		}
		if serves&ServesLoginProfiles != 0 {
			_, err := a.GetLoginProfile(ctx, acct, u.Name, Grant(ctx, t, u.ARN))
			fmt.Fprintf(&b, "  login %v\n", resource.CodeOf(err))
		}
		if serves&ServesEntityPolicies != 0 {
			b.WriteString(boundPolicies(ctx, t, a, iam.EntityUser, u.Name, u.ARN))
		}
	}
	gs, err := a.ListGroups(ctx, acct, "/")
	wantOK(t, "snapshot ListGroups", err)
	for _, g := range gs {
		_, members, err := a.GetGroup(ctx, acct, g.Name, Grant(ctx, t, g.ARN))
		wantOK(t, "snapshot GetGroup", err)
		fmt.Fprintf(&b, "group %s %v\n", g.ARN, userNames(members))
		if serves&ServesEntityPolicies != 0 {
			b.WriteString(boundPolicies(ctx, t, a, iam.EntityGroup, g.Name, g.ARN))
		}
	}
	if serves&ServesRoles != 0 {
		rs, err := a.ListRoles(ctx, acct, "/")
		wantOK(t, "snapshot ListRoles", err)
		for _, r := range rs {
			fmt.Fprintf(&b, "role %s %q %s\n", r.ARN, r.Description, r.TrustPolicy)
			if serves&ServesEntityPolicies != 0 {
				b.WriteString(boundPolicies(ctx, t, a, iam.EntityRole, r.Name, r.ARN))
			}
		}
	}
	return b.String()
}

func boundPolicies(ctx context.Context, t *testing.T, a iam.Directory, kind iam.Entity, name, arn string) string {
	t.Helper()
	ps, err := a.ListAttachedPolicies(ctx, iamAccount(), kind, name, Grant(ctx, t, arn))
	wantOK(t, "snapshot ListAttachedPolicies", err)
	names, err := a.ListInlinePolicies(ctx, iamAccount(), kind, name, Grant(ctx, t, arn))
	wantOK(t, "snapshot ListInlinePolicies", err)
	out := "  inline " + strings.Join(names, ",") + "\n"
	for _, p := range ps {
		out += "  attached " + p.ARN + "\n"
	}
	return out
}
