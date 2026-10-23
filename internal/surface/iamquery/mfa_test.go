package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// noSuchMFADevice is the AWS error shape for a device the account does not
// hold.
const noSuchMFADevice = `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code>` +
	`<Message>The specified MFA device does not exist.</Message></Error><RequestId>`

// AWS GetMFADevice accepts only FIDO security key serial numbers, and no
// backend holds FIDO keys, so an authorized call is NoSuchEntity for a u2f/
// serial and for an enabled virtual mfa/ device alike.
func TestGetMFADevice(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	alice, err := f.CreateUser(ctx, root.Account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	virtual := seedMfaDevice(t, f, root, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, virtual, "alice", now); err != nil {
		t.Fatal(err)
	}
	// The virtual device exists and is enabled: ListVirtualMFADevices shows it.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListVirtualMFADevices"}, "AssignmentStatus": {"Assigned"},
	}), http.StatusOK, `<SerialNumber>`+virtual+`</SerialNumber>`, `<UserName>alice</UserName>`)
	fido := "arn:vws:iam::" + root.Account.String() + ":u2f/alice/testFidoKey-R1234"
	for _, tc := range []struct {
		name, serial, user, authorized string
	}{
		{"a FIDO security key", fido, "", "arn:vws:iam::" + root.Account.String() + ":root"},
		{"a FIDO security key of a named user", fido, "alice", alice.ARN},
		{"an enabled virtual device", virtual, "", "arn:vws:iam::" + root.Account.String() + ":root"},
		{"an enabled virtual device of its owner", virtual, "alice", alice.ARN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {tc.serial}}
			if tc.user != "" {
				form.Set("UserName", tc.user)
			}
			has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusNotFound, noSuchMFADevice)
			if want := "iam:GetMFADevice " + tc.authorized; len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
				t.Errorf("authorized %v, want last %q", rec.seen, want)
			}
		})
	}
}

// The result shape stays the AWS one for when a backend holds FIDO keys.
func TestGetMFADeviceResultShape(t *testing.T) {
	enabled := time.Date(2023, 4, 27, 20, 58, 13, 0, time.UTC)
	out, err := xml.Marshal(toMFADevice(iam.MFADevice{
		UserName: "Bob", SerialNumber: "arn:vws:iam::123456789012:u2f/root/testFidoKey-R1234", Enabled: enabled,
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `<UserName>Bob</UserName><SerialNumber>arn:vws:iam::123456789012:u2f/root/testFidoKey-R1234</SerialNumber>` +
		`<EnableDate>2023-04-27T20:58:13Z</EnableDate><Certifications></Certifications>`
	if !strings.Contains(string(out), want) {
		t.Fatalf("result %s, want %s", out, want)
	}
}

func TestGetMFADeviceErrors(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "error-phone")
	ghost := "arn:vws:iam::" + root.Account.String() + ":mfa/ghost"
	foreign := "arn:vws:iam::210987654321:u2f/alice/testFidoKey-R1234"
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetMFADevice"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	for _, badSerial := range []string{"short", "arn vws:iam::123456789012:u2f/x"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetMFADevice"}, "SerialNumber": {badSerial},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	// A missing, foreign or unassigned device is the same answer.
	for _, missing := range []string{ghost, foreign, serial} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetMFADevice"}, "SerialNumber": {missing},
		}), http.StatusNotFound, noSuchMFADevice)
	}
	// PathPrefix is not an input of this action.
	unsupported := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {serial}, "PathPrefix": {"/"}}
	has(t, call(t, h, root, sigv4.ServiceIAM, unsupported), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
}

// A principal needs iam:GetMFADevice on the user's real ARN, as in AWS: the
// named user, or the caller when UserName is absent. Only then is the answer
// NoSuchEntity.
func TestGetMFADeviceNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	alice, err := f.CreateUser(ctx, root.Account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	virtual := seedMfaDevice(t, f, root, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, virtual, "alice", now); err != nil {
		t.Fatal(err)
	}
	bobUser, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	fido := "arn:vws:iam::" + root.Account.String() + ":u2f/alice/testFidoKey-R1234"
	forAlice := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {fido}, "UserName": {"alice"}}
	self := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {fido}}
	enabledForAlice := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {virtual}, "UserName": {"alice"}}
	has(t, call(t, h, bob, sigv4.ServiceIAM, forAlice), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, self), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	// Permission on bob's own ARN covers bob, not alice.
	policy := `{"Statement":[{"Effect":"Allow","Action":["iam:GetMFADevice"],"Resource":"` + bobUser.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy, ""); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, forAlice), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, self), http.StatusNotFound, noSuchMFADevice)
	// Permission on alice's ARN covers alice, not bob.
	policy = `{"Statement":[{"Effect":"Allow","Action":["iam:GetMFADevice"],"Resource":"` + alice.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy, ""); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, forAlice), http.StatusNotFound, noSuchMFADevice)
	has(t, call(t, h, bob, sigv4.ServiceIAM, enabledForAlice), http.StatusNotFound, noSuchMFADevice)
	has(t, call(t, h, bob, sigv4.ServiceIAM, self), http.StatusForbidden, `<Code>AccessDenied</Code>`)

	t.Run("an unavailable user lookup authorizes nothing", func(t *testing.T) {
		// bob may read user/alice but not anyone under /restricted/. alice is
		// /restricted/alice, so a check on a guessed path-less ARN would let
		// bob through to the 404.
		lookupErr := &resource.Error{Code: resource.CodeUnavailable, Message: "vws-iam is unavailable"}
		h, f, rec, root := harnessWith(t, func(a iam.Admin) iam.Admin {
			return userLookupError{Admin: a, err: lookupErr}
		})
		ctx := t.Context()
		if _, err := f.CreateUser(ctx, root.Account, "alice", "/restricted/"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
			t.Fatal(err)
		}
		users := "arn:vws:iam::" + root.Account.String() + ":user/"
		policy := `{"Statement":[` +
			`{"Effect":"Allow","Action":"iam:GetMFADevice","Resource":"` + users + `alice"},` +
			`{"Effect":"Deny","Action":"iam:GetMFADevice","Resource":"` + users + `restricted/*"}]}`
		if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy, ""); err != nil {
			t.Fatal(err)
		}
		k, err := f.CreateAccessKey(ctx, root.Account, "bob", "")
		if err != nil {
			t.Fatal(err)
		}
		bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
		res := call(t, h, bob, sigv4.ServiceIAM, forAlice)
		if res.Code == http.StatusNotFound {
			t.Fatalf("a failed lookup authorized on a guessed ARN: %d %s", res.Code, res.Body.String())
		}
		has(t, res, http.StatusServiceUnavailable, `<Code>ServiceUnavailable</Code>`)
		if len(rec.seen) != 0 {
			t.Errorf("authorized on a guessed ARN: %v", rec.seen)
		}
	})

	t.Run("a user that does not exist is authorized on the requested name", func(t *testing.T) {
		// AWS evaluates the name it was given; a Deny on it still applies.
		ctx := t.Context()
		policy := `{"Statement":[{"Effect":"Allow","Action":"iam:GetMFADevice","Resource":"*"},` +
			`{"Effect":"Deny","Action":"iam:GetMFADevice","Resource":"arn:vws:iam::` + root.Account.String() + `:user/ghost"}]}`
		if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "get", policy, ""); err != nil {
			t.Fatal(err)
		}
		ghost := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {fido}, "UserName": {"ghost"}}
		has(t, call(t, h, bob, sigv4.ServiceIAM, ghost), http.StatusForbidden, `<Code>AccessDenied</Code>`)
		casper := url.Values{"Action": {"GetMFADevice"}, "SerialNumber": {fido}, "UserName": {"casper"}}
		has(t, call(t, h, bob, sigv4.ServiceIAM, casper), http.StatusNotFound, noSuchMFADevice)
	})
}

// AWS validates SerialNumber before it authorizes, so a malformed serial is
// a 400 even for a caller without iam:GetMFADevice.
func TestGetMFADeviceValidatesBeforeAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	for _, tc := range []struct{ name, serial, msg string }{
		{"missing", "", "failed to satisfy constraint: Member must not be null"},
		{"too short", "u2f/abc", "Member must have length between 9 and 256"},
		{"too long", strings.Repeat("a", 257), "Member must have length between 9 and 256"},
		{"bad character", "arn:vws:iam::123456789012:u2f/alice/key#1", `Member must satisfy regular expression pattern`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec.seen = nil
			form := url.Values{"Action": {"GetMFADevice"}, "UserName": {"bob"}}
			if tc.serial != "" {
				form.Set("SerialNumber", tc.serial)
			}
			has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>ValidationError</Code>`, tc.msg)
			if len(rec.seen) != 0 {
				t.Errorf("authorized before validating: %v", rec.seen)
			}
		})
	}
}
