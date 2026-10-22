package iamclient

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
)

// The IAM Query surface as -iam grpc wires it (cmd/vws-console-api): STSAdmin
// is the admin, and vws-iam authenticates and authorizes. harness's caller is
// the IAM user bob on path /eng/.
const (
	bobARN    = "arn:vws:iam::123456789012:user/eng/bob"
	aliceARN  = "arn:vws:iam::123456789012:user/ops/alice"
	devsARN   = "arn:vws:iam::123456789012:group/team/devs"
	fidoKey   = "arn:vws:iam::123456789012:u2f/user/bob/testFidoKey-R1234"
	vwsIAMMsg = "vws-iam internal wording"
)

var queryNow = time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)

// userActions authorize on a user's ARN and look the user up first. The list
// matches iamquery's TestEntityActionsFailClosedWhenTheLookupFails without
// CreateUser, which authorizes on the ARN it is about to create.
var userActions = []string{
	"AttachUserPolicy", "CreateAccessKey", "CreateLoginProfile", "DeleteAccessKey",
	"DeleteLoginProfile", "DeleteUser", "DeleteUserPolicy", "DetachUserPolicy", "GetLoginProfile",
	"GetMFADevice", "GetUser", "GetUserPolicy", "ListAccessKeys", "ListAttachedUserPolicies",
	"ListGroupsForUser", "ListUserPolicies", "PutUserPolicy", "UpdateLoginProfile", "UpdateUser",
}

// groupActions authorize on a group's ARN and look the group up first; the
// same list without CreateGroup.
var groupActions = []string{
	"AddUserToGroup", "AttachGroupPolicy", "DeleteGroup", "DeleteGroupPolicy",
	"DetachGroupPolicy", "GetGroup", "GetGroupPolicy", "ListAttachedGroupPolicies", "ListGroupPolicies",
	"PutGroupPolicy", "RemoveUserFromGroup", "UpdateGroup",
}

// queryHarness serves the Query surface over a bufconn vws-iam that holds
// bob, alice and the group devs (members alice and a user deleted since).
func queryHarness(t *testing.T) (http.Handler, *server) {
	t.Helper()
	c, s := harness(t)
	created := timestamppb.New(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	s.getUserRes = map[string]*iamv1.User{
		"projects/123456789012/users/bob": {
			Name: "projects/123456789012/users/bob", Spec: &iamv1.UserSpec{Path: "/eng/"},
			Status: &iamv1.UserStatus{Arn: bobARN, UniqueId: "AIDABOB0000000000001"}, CreateTime: created,
		},
		"projects/123456789012/users/alice": {
			Name: "projects/123456789012/users/alice", Spec: &iamv1.UserSpec{Path: "/ops/"},
			Status: &iamv1.UserStatus{Arn: aliceARN, UniqueId: "AIDAALICE00000000001"}, CreateTime: created,
		},
	}
	s.getGroupRes = map[string]*iamv1.Group{
		"projects/123456789012/groups/devs": {
			Name: "projects/123456789012/groups/devs",
			Spec: &iamv1.GroupSpec{Path: "/team/", Members: []string{
				"projects/123456789012/users/alice", "projects/123456789012/users/gone",
			}},
			Status: &iamv1.GroupStatus{Arn: devsARN, UniqueId: "AGPADEVS000000000001"}, CreateTime: created,
		},
	}
	h := iamquery.New(iamquery.Config{
		Admin: STSAdmin{Client: c}, Authorizer: c,
		IAM: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceIAM, Region: resource.RegionName,
			Now: func() time.Time { return queryNow }, Auth: iam.Authenticator(c),
		}),
	})
	s.client = c
	return h, s
}

// queryCall signs form as bob and serves it.
func queryCall(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	form.Set("Version", iamquery.IAMVersion)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8084/",
		strings.NewReader(form.Encode()))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	cred := sigv4.Credential{AccessKey: "AKIABOB", Secret: "bobsecret", Account: account}
	if err := sigv4.Sign(req, cred, sigv4.ServiceIAM, resource.RegionName, queryNow); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, code int, parts ...string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code != code {
		t.Fatalf("status %d, want %d: %s", rec.Code, code, body)
	}
	for _, p := range parts {
		if !strings.Contains(body, p) {
			t.Errorf("missing %q in %s", p, body)
		}
	}
	if strings.Contains(body, vwsIAMMsg) {
		t.Errorf("body echoes vws-iam: %s", body)
	}
}

// authorized lists the action and resources of every Authorize vws-iam saw.
func authorized(s *server) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.authz {
		out = append(out, r.GetAction()+" "+strings.Join(r.GetResources(), ","))
	}
	return out
}

func lookups(s *server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.getUser) + len(s.getGroup)
}

// #179 on the gRPC backend: GetMFADevice through the Query surface with
// STSAdmin reaches authorization for an IAM-user caller and for a named user,
// and answers NoSuchEntity (vws-iam holds no FIDO keys).
func TestGetMFADeviceThroughTheQuerySurfaceOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		user     string
		decision iamv1.Decision
		userErr  error
		status   int
		parts    []string
		authz    []string
		lookups  int
	}{
		{
			// No lookup: the caller is authorized on its own authenticated ARN.
			name: "the calling IAM user", decision: iamv1.Decision_DECISION_ALLOW,
			status: http.StatusNotFound, parts: []string{"<Code>NoSuchEntity</Code>"},
			authz: []string{"iam:GetMFADevice " + bobARN},
		},
		{
			name: "the calling IAM user without permission", decision: iamv1.Decision_DECISION_DENY_IMPLICIT,
			status: http.StatusForbidden, parts: []string{"<Code>AccessDenied</Code>"},
			authz: []string{"iam:GetMFADevice " + bobARN},
		},
		{
			name: "a named user on a path", user: "alice", decision: iamv1.Decision_DECISION_ALLOW,
			status: http.StatusNotFound, parts: []string{"<Code>NoSuchEntity</Code>"},
			authz: []string{"iam:GetMFADevice " + aliceARN}, lookups: 1,
		},
		{
			name: "a named user vws-iam does not hold", user: "ghost", decision: iamv1.Decision_DECISION_ALLOW,
			status: http.StatusNotFound, parts: []string{"<Code>NoSuchEntity</Code>"},
			authz: []string{"iam:GetMFADevice arn:vws:iam::123456789012:user/ghost"}, lookups: 1,
		},
		{
			name: "a named user without permission", user: "alice", decision: iamv1.Decision_DECISION_DENY_EXPLICIT,
			status: http.StatusForbidden, parts: []string{"<Code>AccessDenied</Code>"},
			authz: []string{"iam:GetMFADevice " + aliceARN}, lookups: 1,
		},
		{
			// Fail closed: no authorization on a guessed path-less ARN.
			name: "vws-iam unavailable during the lookup", user: "alice", decision: iamv1.Decision_DECISION_ALLOW,
			userErr: status.Error(codes.Unavailable, vwsIAMMsg),
			status:  http.StatusServiceUnavailable, parts: []string{"<Code>ServiceUnavailable</Code>"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s := queryHarness(t)
			s.decision, s.getUserErr = tc.decision, tc.userErr
			form := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {fidoKey}}
			if tc.user != "" {
				form.Set("UserName", tc.user)
			}
			expect(t, queryCall(t, h, form), tc.status, tc.parts...)
			if got := authorized(s); strings.Join(got, "|") != strings.Join(tc.authz, "|") {
				t.Errorf("authorized %q, want %q", got, tc.authz)
			}
			if got := lookups(s); tc.userErr == nil && got != tc.lookups {
				t.Errorf("%d lookups, want %d", got, tc.lookups)
			}
		})
	}
}

// Every action that authorizes on a user or group ARN reaches vws-iam's
// Authorize on the entity's real ARN, path included, when the gRPC backend
// holds it, and fails closed with 503 when the lookup fails.
func TestEntityActionsAuthorizeOnTheRealARNOverGRPC(t *testing.T) {
	type row struct {
		action, key, name, arn string
	}
	var rows []row
	for _, a := range userActions {
		rows = append(rows, row{a, "UserName", "alice", aliceARN}, row{a, "", "", bobARN})
	}
	for _, a := range groupActions {
		rows = append(rows, row{a, "GroupName", "devs", devsARN})
	}
	for _, r := range rows {
		who := r.name
		if who == "" {
			who = "caller"
		}
		form := func() url.Values {
			f := url.Values{"Action": {r.action}}
			if r.key != "" {
				f.Set(r.key, r.name)
			}
			if r.action == "GetMFADevice" {
				f.Set("SerialNumber", fidoKey)
			}
			return f
		}
		t.Run(r.action+"/"+who+"/denied", func(t *testing.T) {
			h, s := queryHarness(t)
			s.decision = iamv1.Decision_DECISION_DENY_IMPLICIT
			expect(t, queryCall(t, h, form()), http.StatusForbidden, "<Code>AccessDenied</Code>")
			want := "iam:" + r.action + " " + r.arn
			if got := authorized(s); len(got) != 1 || got[0] != want {
				t.Errorf("authorized %q, want [%q]", got, want)
			}
		})
		if r.key == "" {
			continue
		}
		t.Run(r.action+"/"+who+"/lookup unavailable", func(t *testing.T) {
			h, s := queryHarness(t)
			s.getUserErr = status.Error(codes.Unavailable, vwsIAMMsg)
			s.getGroupErr = s.getUserErr
			expect(t, queryCall(t, h, form()), http.StatusServiceUnavailable, "<Code>ServiceUnavailable</Code>")
			if got := authorized(s); len(got) != 0 {
				t.Errorf("authorized on a guessed ARN: %q", got)
			}
		})
	}
}

// GetUser and GetGroup are served over vws-iam's UserService and GroupService.
func TestGetUserAndGetGroupThroughTheQuerySurfaceOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   url.Values
		status int
		parts  []string
	}{
		{
			"GetUser for the caller",
			url.Values{"Action": {"GetUser"}},
			http.StatusOK,
			[]string{
				"<UserName>bob</UserName>", "<Path>/eng/</Path>", "<Arn>" + bobARN + "</Arn>",
				"<UserId>AIDABOB0000000000001</UserId>", "<CreateDate>2026-09-01T00:00:00Z</CreateDate>",
			},
		},
		{
			"GetUser for a named user",
			url.Values{"Action": {"GetUser"}, "UserName": {"alice"}},
			http.StatusOK,
			[]string{"<UserName>alice</UserName>", "<Path>/ops/</Path>", "<Arn>" + aliceARN + "</Arn>"},
		},
		{
			"GetUser for a missing user",
			url.Values{"Action": {"GetUser"}, "UserName": {"ghost"}},
			http.StatusNotFound,
			[]string{"<Code>NoSuchEntity</Code>", "<Message>The user with name ghost cannot be found.</Message>"},
		},
		{
			// A member deleted since is left out, as AWS lists current members.
			"GetGroup",
			url.Values{"Action": {"GetGroup"}, "GroupName": {"devs"}},
			http.StatusOK,
			[]string{
				"<GroupName>devs</GroupName>", "<Path>/team/</Path>", "<Arn>" + devsARN + "</Arn>",
				"<GroupId>AGPADEVS000000000001</GroupId>", "<UserName>alice</UserName>", "<Arn>" + aliceARN + "</Arn>",
			},
		},
		{
			"GetGroup for a missing group",
			url.Values{"Action": {"GetGroup"}, "GroupName": {"ghost"}},
			http.StatusNotFound,
			[]string{"<Code>NoSuchEntity</Code>", "<Message>The group with name ghost cannot be found.</Message>"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := queryHarness(t)
			rec := queryCall(t, h, tc.form)
			expect(t, rec, tc.status, tc.parts...)
			if strings.Contains(rec.Body.String(), "gone") {
				t.Errorf("lists a deleted member: %s", rec.Body)
			}
		})
	}
}
