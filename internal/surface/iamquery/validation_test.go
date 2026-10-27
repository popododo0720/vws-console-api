package iamquery

import (
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
// without permission, and nothing is authorized.
func TestUserNameValidationPrecedesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"bad pattern", "bad#name"},
		{"too long", strings.Repeat("a", 65)},
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

// A UserName at the 64 character limit passes validation and reaches
// authorization, where this caller is denied. The denial proves the name was
// not rejected as too long.
func TestUserNameAtTheLimitReachesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	rec.seen = nil
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"GetUser"}, "UserName": {strings.Repeat("a", 64)},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if len(rec.seen) == 0 {
		t.Error("a 64 character UserName never reached authorization")
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
