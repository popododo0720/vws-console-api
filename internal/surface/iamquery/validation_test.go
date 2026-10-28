package iamquery

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// callerWithoutPermissions creates a user with no policy and returns its
// credential. A request that reaches authorization is AccessDenied and leaves
// an entry in rec.seen.
func callerWithoutPermissions(t *testing.T, f *iam.Fake, root sigv4.Credential) sigv4.Credential {
	t.Helper()
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	return sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
}

// AWS validates UserName before it authorizes, so a malformed or too-long name
// is 400 ValidationError for every action that takes one, even for a caller
// without permission, and nothing is authorized. 129 characters is past the
// limit of every action; the per-action limits are in
// TestUserNameLengthFollowsTheAWSLimitOfEachAction.
func TestUserNameValidationPrecedesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"bad pattern", "bad#name"},
		{"too long", strings.Repeat("a", 129)},
		{"empty", ""},
	} {
		for action, spec := range iamActions() {
			if !slices.Contains(spec.params, "UserName") {
				continue
			}
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				rec.seen = nil
				has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
					"Action": {action}, "UserName": {tc.value},
				}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
				if len(rec.seen) != 0 {
					t.Errorf("UserName %q was authorized before validation: %v", tc.value, rec.seen)
				}
			})
		}
	}
}

// awsUserNameMax is the UserName maximum length of each served action, from
// the AWS IAM API reference: userNameType actions take 1 to 64 characters,
// existingUserNameType actions 1 to 128. A served action that takes UserName
// and is missing here fails the test, so a new action is classified from the
// AWS documentation rather than defaulted.
var awsUserNameMax = map[string]int{
	"AttachUserPolicy":         64,
	"CreateLoginProfile":       64,
	"CreateUser":               64,
	"DeleteLoginProfile":       64,
	"DetachUserPolicy":         64,
	"GetLoginProfile":          64,
	"GetMFADevice":             64,
	"ListAttachedUserPolicies": 64,
	"UpdateLoginProfile":       64,
	"AddUserToGroup":           128,
	"CreateAccessKey":          128,
	"DeleteAccessKey":          128,
	"DeleteUser":               128,
	"DeleteUserPolicy":         128,
	"GetUser":                  128,
	"GetUserPolicy":            128,
	"ListAccessKeys":           128,
	"ListGroupsForUser":        128,
	"ListMFADevices":           128,
	"ListUserPolicies":         128,
	"PutUserPolicy":            128,
	"RemoveUserFromGroup":      128,
	"UpdateAccessKey":          128,
	"UpdateUser":               128,
}

// AWS limits UserName per action, so a name up to the action's limit passes
// validation and reaches authorization, where this caller is denied, and one
// character more is 400 ValidationError with nothing authorized. A 65 to 128
// character name is valid on a 128-limit action such as GetUser or
// ListMFADevices and is looked up or denied, not refused as malformed.
func TestUserNameLengthFollowsTheAWSLimitOfEachAction(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	// Other members an action checks before it authorizes, set to valid values
	// so only UserName decides the outcome.
	extra := map[string]url.Values{
		"GetMFADevice": {"SerialNumber": {"arn:aws:iam::123456789012:mfa/device"}},
	}
	for action, spec := range iamActions() {
		if !slices.Contains(spec.params, "UserName") {
			continue
		}
		limit, ok := awsUserNameMax[action]
		if !ok {
			t.Errorf("%s takes UserName but has no AWS limit in awsUserNameMax", action)
			continue
		}
		for _, n := range []int{64, 65, 128, 129} {
			t.Run(fmt.Sprintf("%s/%d", action, n), func(t *testing.T) {
				q := url.Values{"Action": {action}, "UserName": {strings.Repeat("a", n)}}
				for k, v := range extra[action] {
					q[k] = v
				}
				rec.seen = nil
				resp := call(t, h, bob, sigv4.ServiceIAM, q)
				if n > limit {
					has(t, resp, http.StatusBadRequest, `<Code>ValidationError</Code>`,
						fmt.Sprintf("Member must have length less than or equal to %d", limit))
					if len(rec.seen) != 0 {
						t.Errorf("a %d character UserName was authorized past the %d limit: %v", n, limit, rec.seen)
					}
					return
				}
				has(t, resp, http.StatusForbidden, `<Code>AccessDenied</Code>`)
				if len(rec.seen) == 0 {
					t.Errorf("a %d character UserName never reached authorization (limit %d)", n, limit)
				}
			})
		}
	}
}

// AWS validates SerialNumber before it authorizes, so the MFA device tag
// actions answer a malformed serial with 400 ValidationError instead of the
// AccessDenied a caller without permission would get.
func TestMFADeviceTagSerialValidationPrecedesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	for _, action := range []string{"TagMFADevice", "UntagMFADevice", "ListMFADeviceTags"} {
		for _, serial := range []string{"", "short", "arn vws:iam::123456789012:mfa/x"} {
			t.Run(action+"/"+serial, func(t *testing.T) {
				rec.seen = nil
				has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
					"Action": {action}, "SerialNumber": {serial},
				}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
				if len(rec.seen) != 0 {
					t.Errorf("SerialNumber %q was authorized before validation: %v", serial, rec.seen)
				}
			})
		}
	}
}
