package iamquery

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"slices"
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
			res:  []func(*handler, *exchange) string{userARN}, key: "UserName",
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
