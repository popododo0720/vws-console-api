package iamclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
)

// dirQueryHarness serves the Query surface with STSAdmin over a directory
// that holds bob (/eng/, the caller), alice (/ops/) and devs (/team/, member
// alice); vws-iam's AuthService (harness) authenticates and authorizes.
func dirQueryHarness(t *testing.T) (http.Handler, *server, *directory) {
	t.Helper()
	return dirQueryHarnessWith(t, nil)
}

// dirQueryHarnessWith is dirQueryHarness with the Admin the surface calls
// wrapped by wrap, when it is not nil.
func dirQueryHarnessWith(t *testing.T, wrap func(iam.Directory) iam.Directory) (http.Handler, *server, *directory) {
	t.Helper()
	auth, s := harness(t)
	seededAdmin, d := seeded(t.Context(), t)
	var admin iam.Directory = seededAdmin
	if wrap != nil {
		admin = wrap(seededAdmin)
	}
	verifier := func(svc sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{
			Service: svc, Region: resource.RegionName,
			Now: func() time.Time { return queryNow }, Auth: iam.Authenticator(auth),
		})
	}
	h := iamquery.New(iamquery.Config{
		Admin: admin, Authorizer: auth,
		IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS),
	})
	return h, s, d
}

// Bundle 1 of #314 is served through the Query surface over gRPC with the
// AWS IAM shapes, codes and paging.
func TestUserAndGroupActionsThroughTheQuerySurfaceOverGRPC(t *testing.T) {
	type step struct {
		form   url.Values
		status int
		parts  []string
	}
	f := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"CreateUser", []step{
			{f("Action", "CreateUser", "UserName", "carol", "Path", "/qa/"), 200, []string{
				"<CreateUserResponse", "<UserName>carol</UserName>", "<Path>/qa/</Path>",
				"<Arn>arn:vws:iam::123456789012:user/qa/carol</Arn>", "<UserId>AIDA", "<CreateDate>",
			}},
			{f("Action", "CreateUser", "UserName", "CAROL"), 409, []string{
				"<Code>EntityAlreadyExists</Code>", "User with name CAROL already exists.",
			}},
			{f("Action", "CreateUser"), 400, []string{"<Code>ValidationError</Code>", "userName"}},
			{f("Action", "CreateUser", "UserName", "bad name"), 400, []string{"<Code>ValidationError</Code>"}},
			{f("Action", "CreateUser", "UserName", "dave", "Path", "qa"), 400, []string{"<Code>InvalidInput</Code>"}},
		}},
		{"ListUsers pages", []step{
			{f("Action", "ListUsers", "MaxItems", "1"), 200, []string{
				"<UserName>alice</UserName>", "<IsTruncated>true</IsTruncated>", "<Marker>alice</Marker>",
			}},
			{f("Action", "ListUsers", "Marker", "alice"), 200, []string{
				"<UserName>bob</UserName>", "<IsTruncated>false</IsTruncated>",
			}},
			{f("Action", "ListUsers", "PathPrefix", "/ops/"), 200, []string{"<UserName>alice</UserName>"}},
			{f("Action", "ListUsers", "MaxItems", "0"), 400, []string{"<Code>ValidationError</Code>"}},
			{f("Action", "ListUsers", "MaxItems", "1001"), 400, []string{"<Code>ValidationError</Code>"}},
			{f("Action", "ListUsers", "PathPrefix", "ops"), 400, []string{"<Code>ValidationError</Code>"}},
		}},
		{"UpdateUser and DeleteUser", []step{
			{f("Action", "UpdateUser", "UserName", "bob", "NewPath", "/sre/"), 200, []string{"<UpdateUserResponse"}},
			{f("Action", "GetUser", "UserName", "bob"), 200, []string{"<Path>/sre/</Path>"}},
			{f("Action", "UpdateUser", "UserName", "bob", "NewUserName", "robert"), 400, []string{
				"<Code>InvalidAction</Code>",
			}},
			{f("Action", "UpdateUser", "UserName", "ghost", "NewPath", "/"), 404, []string{"<Code>NoSuchEntity</Code>"}},
			{f("Action", "DeleteUser", "UserName", "alice"), 409, []string{
				"<Code>DeleteConflict</Code>", iam.UserDeleteConflict,
			}},
			{f("Action", "DeleteUser", "UserName", "bob"), 200, []string{"<DeleteUserResponse"}},
			{f("Action", "DeleteUser", "UserName", "bob"), 404, []string{"<Code>NoSuchEntity</Code>"}},
		}},
		{"groups", []step{
			{f("Action", "CreateGroup", "GroupName", "ops", "Path", "/x/"), 200, []string{
				"<GroupName>ops</GroupName>", "<Arn>arn:vws:iam::123456789012:group/x/ops</Arn>", "<GroupId>AGPA",
			}},
			{f("Action", "CreateGroup", "GroupName", "ops"), 409, []string{"<Code>EntityAlreadyExists</Code>"}},
			{f("Action", "ListGroups", "MaxItems", "1"), 200, []string{
				"<GroupName>devs</GroupName>", "<IsTruncated>true</IsTruncated>", "<Marker>devs</Marker>",
			}},
			{f("Action", "AddUserToGroup", "GroupName", "ops", "UserName", "bob"), 200, []string{"<AddUserToGroupResponse"}},
			{f("Action", "AddUserToGroup", "GroupName", "ops", "UserName", "ghost"), 404, []string{"<Code>NoSuchEntity</Code>"}},
			{f("Action", "ListGroupsForUser", "UserName", "bob"), 200, []string{"<GroupName>ops</GroupName>"}},
			{f("Action", "GetGroup", "GroupName", "ops"), 200, []string{"<UserName>bob</UserName>"}},
			{f("Action", "DeleteGroup", "GroupName", "ops"), 409, []string{"<Code>DeleteConflict</Code>"}},
			{f("Action", "RemoveUserFromGroup", "GroupName", "ops", "UserName", "bob"), 200, []string{
				"<RemoveUserFromGroupResponse",
			}},
			{f("Action", "UpdateGroup", "GroupName", "ops", "NewPath", "/y/"), 200, []string{"<UpdateGroupResponse"}},
			{
				f("Action", "UpdateGroup", "GroupName", "ops", "NewGroupName", "ops2"), 400,
				[]string{"<Code>InvalidAction</Code>"},
			},
			{f("Action", "DeleteGroup", "GroupName", "ops"), 200, []string{"<DeleteGroupResponse"}},
			{f("Action", "GetGroup", "GroupName", "ops"), 404, []string{"<Code>NoSuchEntity</Code>"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := dirQueryHarness(t)
			for i, st := range tc.steps {
				rec := queryCall(t, h, st.form)
				if rec.Code != st.status {
					t.Fatalf("step %d %v: status %d, want %d: %s", i, st.form, rec.Code, st.status, rec.Body)
				}
				for _, p := range st.parts {
					if !strings.Contains(rec.Body.String(), p) {
						t.Errorf("step %d %v: missing %q in %s", i, st.form, p, rec.Body)
					}
				}
			}
		})
	}
}

// A denied or unauthorizable call changes nothing in vws-iam.
func TestUserAndGroupChangesFailClosedOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*server)
		status int
		code   string
	}{
		{"denied", func(s *server) { s.decision = iamv1.Decision_DECISION_DENY_EXPLICIT }, 403, "AccessDenied"},
		{"no decision", func(s *server) { s.decision = iamv1.Decision_DECISION_UNSPECIFIED }, 403, "AccessDenied"},
		{"AuthService unavailable", func(s *server) { s.failFirst = 100 }, 503, "ServiceUnavailable"},
	} {
		for _, form := range []url.Values{
			{"Action": {"CreateUser"}, "UserName": {"carol"}},
			{"Action": {"DeleteUser"}, "UserName": {"bob"}},
			{"Action": {"UpdateUser"}, "UserName": {"bob"}, "NewPath": {"/x/"}},
			{"Action": {"CreateGroup"}, "GroupName": {"ops"}},
			{"Action": {"DeleteGroup"}, "GroupName": {"devs"}},
			{"Action": {"AddUserToGroup"}, "GroupName": {"devs"}, "UserName": {"bob"}},
			{"Action": {"RemoveUserFromGroup"}, "GroupName": {"devs"}, "UserName": {"alice"}},
			{"Action": {"ListUsers"}},
		} {
			t.Run(tc.name+"/"+form.Get("Action"), func(t *testing.T) {
				h, s, d := dirQueryHarness(t)
				s.mu.Lock()
				tc.set(s)
				s.mu.Unlock()
				before := len(d.sent("CreateUser")) + len(d.sent("CreateGroup")) + len(d.sent("UpdateGroup"))
				expect(t, queryCall(t, h, form), tc.status, "<Code>"+tc.code+"</Code>")
				after := len(d.sent("CreateUser")) + len(d.sent("CreateGroup")) + len(d.sent("UpdateGroup"))
				for _, m := range []string{"DeleteUser", "DeleteGroup", "UpdateUser", "ListUsers"} {
					after += len(d.sent(m))
				}
				if after != before {
					t.Errorf("%d changes or lists reached vws-iam", after-before)
				}
			})
		}
	}
}
