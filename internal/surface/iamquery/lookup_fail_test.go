package iamquery

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// userLookupError answers every GetUser with err, as when vws-iam is down.
type userLookupError struct {
	iam.Admin
	err error
}

func (u userLookupError) GetUser(context.Context, resource.AccountID, string) (iam.User, error) {
	return iam.User{}, u.err
}

// groupLookupError answers every GetGroup with err.
type groupLookupError struct {
	iam.Admin
	err error
}

func (g groupLookupError) GetGroup(context.Context, resource.AccountID, string) (iam.Group, []iam.User, error) {
	return iam.Group{}, nil, g.err
}

// actionsOn lists the IAM actions whose spec authorizes through one of res.
func actionsOn(res ...func(*handler, *exchange) string) []string {
	var out []string
	for name, s := range actionTable()[sigv4.ServiceIAM] {
		if s.resource == nil {
			continue
		}
		got := reflect.ValueOf(s.resource).Pointer()
		for _, r := range res {
			if reflect.ValueOf(r).Pointer() == got {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// A lookup that fails for any reason but NoSuchEntity must not authorize on
// a guessed path-less ARN: a Deny on the entity's real path would be skipped.
// The call fails closed with the lookup's error.
func TestEntityActionsFailClosedWhenTheLookupFails(t *testing.T) {
	lookupErr := &resource.Error{Code: resource.CodeUnavailable, Message: "vws-iam is unavailable"}
	for _, tc := range []struct {
		name   string
		res    []func(*handler, *exchange) string
		key    string
		wrap   func(iam.Admin) iam.Admin
		skip   []string
		expect []string
	}{
		{
			name: "user",
			// GetMFADevice checks its serial first, then authorizes on the user.
			res: []func(*handler, *exchange) string{userARN, getMFADeviceARN}, key: "UserName",
			wrap: func(a iam.Admin) iam.Admin { return userLookupError{Admin: a, err: lookupErr} },
			// CreateUser authorizes on the ARN it is about to create.
			skip: []string{"CreateUser"},
			expect: []string{
				"AttachUserPolicy", "CreateAccessKey", "CreateLoginProfile", "CreateUser", "DeleteAccessKey",
				"DeleteLoginProfile", "DeleteUser", "DeleteUserPolicy", "DetachUserPolicy", "GetLoginProfile",
				"GetMFADevice", "GetUser", "GetUserPolicy", "ListAccessKeys", "ListAttachedUserPolicies",
				"ListGroupsForUser", "ListUserPolicies", "PutUserPolicy", "UpdateLoginProfile", "UpdateUser",
			},
		},
		{
			name: "group", res: []func(*handler, *exchange) string{groupARN}, key: "GroupName",
			wrap: func(a iam.Admin) iam.Admin { return groupLookupError{Admin: a, err: lookupErr} },
			skip: []string{"CreateGroup"},
			expect: []string{
				"AddUserToGroup", "AttachGroupPolicy", "CreateGroup", "DeleteGroup", "DeleteGroupPolicy",
				"DetachGroupPolicy", "GetGroup", "GetGroupPolicy", "ListAttachedGroupPolicies", "ListGroupPolicies",
				"PutGroupPolicy", "RemoveUserFromGroup", "UpdateGroup",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions := actionsOn(tc.res...)
			if !slices.Equal(actions, tc.expect) {
				t.Fatalf("actions on %s ARNs: %q, want %q (add a row)", tc.name, actions, tc.expect)
			}
			h, _, rec, root := harnessWith(t, tc.wrap)
			for _, action := range actions {
				if slices.Contains(tc.skip, action) {
					continue
				}
				t.Run(action, func(t *testing.T) {
					rec.seen = nil
					form := url.Values{"Action": {action}, tc.key: {"alice"}}
					if action == "GetMFADevice" {
						form.Set("SerialNumber", "arn:vws:iam::"+root.Account.String()+":u2f/alice/testFidoKey-R1234")
					}
					has(t, call(t, h, root, sigv4.ServiceIAM, form),
						http.StatusServiceUnavailable, `<Code>ServiceUnavailable</Code>`)
					if len(rec.seen) != 0 {
						t.Errorf("authorized on a guessed ARN: %v", rec.seen)
					}
				})
			}
		})
	}
}

// Without UserName a user action is about the caller, authorized on its own
// authenticated ARN with no lookup, as in AWS. A lookup that would fail (on
// -iam grpc, vws-iam not serving GetUser or being down) must not turn the
// caller's own call into an error before authorization (PR #311 review).
func TestCallerActionsAuthorizeOnTheCallerWithoutALookup(t *testing.T) {
	lookupErr := &resource.Error{Code: resource.CodeUnimplemented, Message: "GetUser is not served"}
	h, f, rec, root := harnessWith(t, func(a iam.Admin) iam.Admin { return userLookupError{Admin: a, err: lookupErr} })
	ctx := t.Context()
	bob, err := f.CreateUser(ctx, root.Account, "bob", "/eng/")
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	for _, action := range actionsOn(userARN, getMFADeviceARN) {
		if action == "CreateUser" {
			continue
		}
		t.Run(action, func(t *testing.T) {
			rec.seen = nil
			form := url.Values{"Action": {action}}
			if action == "GetMFADevice" {
				form.Set("SerialNumber", "arn:vws:iam::"+root.Account.String()+":u2f/bob/testFidoKey-R1234")
			}
			// bob holds no policy: the answer is AccessDenied on bob's ARN.
			has(t, call(t, h, cred, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
			want := []string{"iam:" + action + " " + bob.ARN}
			if !slices.Equal(rec.seen, want) {
				t.Errorf("authorized %q, want %q", rec.seen, want)
			}
		})
	}
}

// A lookup that fails with something other than an IAM error (the gRPC
// client's error for vws-iam being down or timing out) answers
// ServiceUnavailable, as iam.Check does for authorization, not a 500, and
// does not echo the backend's message.
func TestLookupOutageAnswersServiceUnavailable(t *testing.T) {
	outage := errors.New("vws-iam: Unavailable backend-internal-wording")
	for _, tc := range []struct {
		key  string
		res  []func(*handler, *exchange) string
		skip string
		wrap func(iam.Admin) iam.Admin
	}{
		{
			"UserName",
			[]func(*handler, *exchange) string{userARN, getMFADeviceARN},
			"CreateUser",
			func(a iam.Admin) iam.Admin { return userLookupError{Admin: a, err: outage} },
		},
		{
			"GroupName",
			[]func(*handler, *exchange) string{groupARN},
			"CreateGroup",
			func(a iam.Admin) iam.Admin { return groupLookupError{Admin: a, err: outage} },
		},
	} {
		h, _, rec, root := harnessWith(t, tc.wrap)
		for _, action := range actionsOn(tc.res...) {
			if action == tc.skip {
				continue
			}
			t.Run(action, func(t *testing.T) {
				rec.seen = nil
				form := url.Values{"Action": {action}, tc.key: {"alice"}}
				if action == "GetMFADevice" {
					form.Set("SerialNumber", "arn:vws:iam::"+root.Account.String()+":u2f/alice/testFidoKey-R1234")
				}
				res := call(t, h, root, sigv4.ServiceIAM, form)
				has(t, res, http.StatusServiceUnavailable, `<Code>ServiceUnavailable</Code>`)
				if strings.Contains(res.Body.String(), "backend-internal-wording") {
					t.Errorf("body echoes the backend: %s", res.Body)
				}
				if len(rec.seen) != 0 {
					t.Errorf("authorized on a guessed ARN: %v", rec.seen)
				}
			})
		}
	}
}
