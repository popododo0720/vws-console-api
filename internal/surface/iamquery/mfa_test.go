package iamquery

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestGetMFADevice(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	alice, err := f.CreateUser(ctx, root.Account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	serial := seedMfaDevice(t, f, root, "alice-phone")
	if _, err := f.EnableMfaDevice(root.Account, serial, "alice"); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}})
	has(t, res, http.StatusOK,
		`<GetMFADeviceResponse><GetMFADeviceResult><UserName>alice</UserName>`+
			`<SerialNumber>`+serial+`</SerialNumber>`+
			`<EnableDate>2026-10-09T10:00:00Z</EnableDate>`+
			`<Certifications></Certifications></GetMFADeviceResult>`+
			`<ResponseMetadata><RequestId>`,
	)
	if want := "iam:GetMFADevice " + alice.ARN; len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	// UserName names the device's owner.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "UserName": {"alice"},
	}), http.StatusOK, `<UserName>alice</UserName>`)
	// Another user does not have the device.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "UserName": {"bob"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
}

func TestGetMFADeviceErrors(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "error-phone")
	ghost := "arn:vws:iam::" + root.Account.String() + ":mfa/ghost"
	foreign := "arn:vws:iam::210987654321:mfa/error-phone"
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetMFADevice"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	for _, badSerial := range []string{"short", "arn vws:iam::123456789012:mfa/x"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetMFADevice"}, "SerialNumber": {badSerial},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	for _, missing := range []string{ghost, foreign} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetMFADevice"}, "SerialNumber": {missing},
		}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	}
	// An unassigned device has no owner to answer for.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetMFADevice"}, "SerialNumber": {serial},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	// PathPrefix is not an input of this action.
	unsupported := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "PathPrefix": {"/"}}
	has(t, call(t, h, root, sigv4.ServiceIAM, unsupported), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
}

// A principal needs iam:GetMFADevice on the owning user's ARN, as in AWS.
func TestGetMFADeviceNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	alice, err := f.CreateUser(ctx, root.Account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	serial := seedMfaDevice(t, f, root, "alice-phone")
	if _, err := f.EnableMfaDevice(root.Account, serial, "alice"); err != nil {
		t.Fatal(err)
	}
	bobUser, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	form := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}}
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	// Permission on bob's own ARN does not cover alice's device.
	policy := `{"Statement":[{"Effect":"Allow","Action":["iam:GetMFADevice"],"Resource":"` + bobUser.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	// Permission on the owner's ARN does.
	policy = `{"Statement":[{"Effect":"Allow","Action":["iam:GetMFADevice"],"Resource":"` + alice.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusOK, `<UserName>alice</UserName>`)
	// A missing device is not authorized on a guessed ARN.
	ghost := "arn:vws:iam::" + root.Account.String() + ":mfa/ghost"
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"GetMFADevice"}, "SerialNumber": {ghost},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
}
