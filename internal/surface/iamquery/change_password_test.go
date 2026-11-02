package iamquery

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// changePasswordUser makes user bob with a login profile and a policy
// document; it returns bob's signing credential.
func changePasswordUser(t *testing.T, f *iam.Fake, root sigv4.Credential, policy string) sigv4.Credential {
	t.Helper()
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/eng/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(ctx, root.Account, "bob", "old password 1",
		backendtest.UserGrant(ctx, t, f, root.Account, "bob")); err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "p", policy,
		backendtest.EntityGrant(ctx, t, f, root.Account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	return sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
}

// changePolicy allows iam:ChangePassword on the user ARN arn.
func changePolicy(arn string) string {
	return `{"Statement":[{"Effect":"Allow","Action":"iam:ChangePassword","Resource":"` + arn + `"}]}`
}

var selfChangePolicy = changePolicy("arn:vws:iam::123456789012:user/eng/bob")

func changePassword(oldPw, newPw string) url.Values {
	return url.Values{"Action": {"ChangePassword"}, "OldPassword": {oldPw}, "NewPassword": {newPw}}
}

// noSecrets fails when a response carries a password the request sent.
func noSecrets(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(body, s) {
			t.Fatalf("response echoes a password: %s", body)
		}
	}
}

func TestChangePasswordChangesCallersOwnPassword(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := changePasswordUser(t, f, root, selfChangePolicy)

	res := call(t, h, bob, sigv4.ServiceIAM, changePassword("old password 1", "new password 2"))
	has(t, res, http.StatusOK,
		`<ChangePasswordResponse><ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), "ChangePasswordResult") {
		t.Errorf("ChangePassword has no result element in AWS: %s", res.Body.String())
	}
	noSecrets(t, res.Body.String(), "old password 1", "new password 2")
	if !strings.Contains(strings.Join(rec.seen, "\n"), "iam:ChangePassword arn:vws:iam::123456789012:user/eng/bob") {
		t.Errorf("not authorized on the caller's own ARN: %v", rec.seen)
	}

	// The old password no longer verifies; the new one does.
	res = call(t, h, bob, sigv4.ServiceIAM, changePassword("old password 1", "third password 3"))
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`, `the old password was incorrect`)
	noSecrets(t, res.Body.String(), "old password 1", "third password 3")
	has(t, call(t, h, bob, sigv4.ServiceIAM, changePassword("new password 2", "third password 3")), http.StatusOK)
}

func TestChangePasswordErrors(t *testing.T) {
	h, f, _, root := harness(t)
	bob := changePasswordUser(t, f, root, selfChangePolicy)
	long := strings.Repeat("a", 129)
	const bad, forbidden, ve = http.StatusBadRequest, http.StatusForbidden, "ValidationError"
	only := func(k, v string) url.Values { return url.Values{"Action": {"ChangePassword"}, k: {v}} }
	for _, tc := range []struct {
		name   string
		cred   sigv4.Credential
		form   url.Values
		status int
		code   string
	}{
		{"root is not an IAM user", root, changePassword("old password 1", "new password 2"), bad, "InvalidUserType"},
		{"policy violation", bob, changePassword("old password 1", "short"), bad, "PasswordPolicyViolation"},
		{"wrong old password", bob, changePassword("wrong password", "new password 2"), forbidden, "AccessDenied"},
		{"missing NewPassword", bob, only("OldPassword", "old password 1"), bad, ve},
		{"missing OldPassword", bob, only("NewPassword", "new password 2"), bad, ve},
		{"NewPassword too long", bob, changePassword("old password 1", long), bad, ve},
		{"OldPassword bad character", bob, changePassword("old\x01password", "new password 2"), bad, ve},
		{"UserName is not a member", bob, url.Values{
			"Action": {"ChangePassword"}, "UserName": {"bob"},
			"OldPassword": {"old password 1"}, "NewPassword": {"new password 2"},
		}, bad, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := call(t, h, tc.cred, sigv4.ServiceIAM, tc.form)
			has(t, res, tc.status, "<Code>"+tc.code+"</Code>")
			noSecrets(t, res.Body.String(), "old password 1", "new password 2", "wrong password", long)
		})
	}
	// None of the failures changed the password.
	has(t, call(t, h, bob, sigv4.ServiceIAM, changePassword("old password 1", "new password 2")), http.StatusOK)
}

func TestChangePasswordNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	other := changePolicy("arn:vws:iam::123456789012:user/eng/alice")
	bob := changePasswordUser(t, f, root, other)
	has(t, call(t, h, bob, sigv4.ServiceIAM, changePassword("old password 1", "new password 2")),
		http.StatusForbidden, `<Code>AccessDenied</Code>`)
}

func TestChangePasswordWithoutLoginProfile(t *testing.T) {
	h, f, _, root := harness(t)
	bob := changePasswordUser(t, f, root, selfChangePolicy)
	if err := f.DeleteLoginProfile(t.Context(), root.Account, "bob",
		backendtest.UserGrant(t.Context(), t, f, root.Account, "bob")); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, changePassword("old password 1", "new password 2")),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`, "Login Profile for User with name bob")
}
