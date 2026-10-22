package iamquery

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// AWS accepts only FIDO security-key ARNs for GetMFADevice, and vws-iam keeps
// no FIDO keys. A virtual device the fake holds and has enabled is not an
// answer AWS returns, so every serial is NoSuchEntity.
func TestGetMFADeviceAnswersNoSuchEntity(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	serial := seedMfaDevice(t, f, root, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, serial, "alice", now); err != nil {
		t.Fatal(err)
	}
	fido := "arn:vws:iam::" + root.Account.String() + ":u2f/root/testFidoKey-R1234"
	ghost := "arn:vws:iam::" + root.Account.String() + ":mfa/ghost"
	for _, tc := range []struct{ name, serial string }{
		{"enabled virtual device", serial},
		{"FIDO security key", fido},
		{"missing device", ghost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
				"Action": {"GetMFADevice"}, "SerialNumber": {tc.serial},
			}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
		})
	}
	// UserName is an accepted input, and it does not turn a virtual device
	// into an answer either.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "UserName": {"alice"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	// The action authorizes on the device ARN, the SerialNumber.
	if want := "iam:GetMFADevice " + fido; !slices.Contains(rec.seen, want) {
		t.Errorf("authorized %v, want %q", rec.seen, want)
	}
}

func TestGetMFADeviceErrors(t *testing.T) {
	h, _, _, root := harness(t)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetMFADevice"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	for _, badSerial := range []string{"short", "arn vws:iam::123456789012:mfa/x"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetMFADevice"}, "SerialNumber": {badSerial},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	// PathPrefix is not an input of this action.
	serial := "arn:vws:iam::" + root.Account.String() + ":mfa/alice-phone"
	unsupported := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "PathPrefix": {"/"}}
	has(t, call(t, h, root, sigv4.ServiceIAM, unsupported), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
}

// A caller needs iam:GetMFADevice on the device ARN before the action answers.
func TestGetMFADeviceNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	serial := "arn:vws:iam::" + root.Account.String() + ":u2f/root/testFidoKey-R1234"
	form := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}}
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	policy := `{"Statement":[{"Effect":"Allow","Action":["iam:GetMFADevice"],"Resource":"` + serial + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
}
