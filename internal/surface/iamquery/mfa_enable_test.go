package iamquery

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var enableSeed = []byte("12345678901234567890")

// enableForm is an EnableMFADevice request with two consecutive codes of
// enableSeed at the harness time.
func enableForm(user, serial string) url.Values {
	return url.Values{
		"Action": {"EnableMFADevice"}, "UserName": {user}, "SerialNumber": {serial},
		"AuthenticationCode1": {iam.TOTPCode(enableSeed, now.Add(-30*time.Second))},
		"AuthenticationCode2": {iam.TOTPCode(enableSeed, now)},
	}
}

// EnableMFADevice answers an empty result in the AWS envelope, is authorized
// as iam:EnableMFADevice on the user, and the device is then listed as the
// user's. Neither code appears in the response.
func TestEnableMFADevice(t *testing.T) {
	h, f, rec, root := harness(t)
	if _, err := f.CreateUser(t.Context(), root.Account, "alice", "/eng/"); err != nil {
		t.Fatal(err)
	}
	serial := f.AddTOTPMfaDevice(root.Account, "alice-phone", enableSeed)
	form := enableForm("alice", serial)
	res := call(t, h, root, sigv4.ServiceIAM, form)
	has(t, res, http.StatusOK, `<EnableMFADeviceResponse>`,
		`<ResponseMetadata><RequestId>`)
	body := res.Body.String()
	if strings.Contains(body, "<EnableMFADeviceResult>") ||
		strings.Contains(body, form.Get("AuthenticationCode1")) || strings.Contains(body, form.Get("AuthenticationCode2")) {
		t.Errorf("EnableMFADevice returned more than the empty AWS result: %s", body)
	}
	want := "iam:EnableMFADevice arn:vws:iam::123456789012:user/eng/alice"
	if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
		t.Errorf("not authorized as %s: %v", want, rec.seen)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}),
		http.StatusOK, `<SerialNumber>`+serial+`</SerialNumber>`)
}

// Each documented error maps to its AWS code and HTTP status.
func TestEnableMFADeviceErrors(t *testing.T) {
	h, f, _, root := harness(t)
	for _, u := range []string{"alice", "bob"} {
		if _, err := f.CreateUser(t.Context(), root.Account, u, "/"); err != nil {
			t.Fatal(err)
		}
	}
	serial := f.AddTOTPMfaDevice(root.Account, "alice-phone", enableSeed)
	inUse := f.AddTOTPMfaDevice(root.Account, "bob-phone", enableSeed)
	if err := f.AssignMfaDevice(root.Account, inUse, "bob", now); err != nil {
		t.Fatal(err)
	}
	wrong := enableForm("alice", serial)
	wrong.Set("AuthenticationCode1", "000000")
	res := call(t, h, root, sigv4.ServiceIAM, wrong)
	has(t, res, http.StatusForbidden, `<Code>InvalidAuthenticationCode</Code>`, `<Type>Sender</Type>`)
	if strings.Contains(res.Body.String(), wrong.Get("AuthenticationCode2")) {
		t.Errorf("error echoes a code: %s", res.Body.String())
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, enableForm("alice", inUse)),
		http.StatusConflict, `<Code>EntityAlreadyExists</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, enableForm("nobody", serial)),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`, `<Message>The user with name nobody cannot be found.</Message>`)
	for name, other := range map[string]string{
		"missing":       "arn:vws:iam::123456789012:mfa/ghost-phone",
		"other account": "arn:vws:iam::210987654321:mfa/alice-phone",
		"other path":    "arn:vws:iam::123456789012:mfa/eng/alice-phone",
	} {
		t.Run(name, func(t *testing.T) {
			has(t, call(t, h, root, sigv4.ServiceIAM, enableForm("alice", other)),
				http.StatusNotFound, `<Code>NoSuchEntity</Code>`, `<Message>The specified MFA device does not exist.</Message>`)
		})
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}),
		http.StatusOK, `<MFADevices></MFADevices>`)
}

// stubEnable answers EnableMFADevice with a fixed error, for the errors the
// fake cannot reach: a user renamed or made again, a lost race, a backend
// fault.
type stubEnable struct {
	iam.Directory
	err error
}

func (s stubEnable) EnableMFADevice(
	context.Context, resource.AccountID, string, string, string, string, iam.AuthorizedPrincipal,
) error {
	return s.err
}

func TestEnableMFADeviceBackendErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{
			"user temporarily unmodifiable", iam.UserTemporarilyUnmodifiable("alice"),
			http.StatusConflict, "EntityTemporarilyUnmodifiable",
		},
		{"user moved", iam.Changed(iam.UserChanged), http.StatusConflict, "ConcurrentModification"},
		{
			"limit", &resource.Error{Code: resource.CodeResourceExhausted, Message: "too many devices"},
			http.StatusConflict, "LimitExceeded",
		},
		{"backend fault", resource.Internal(context.DeadlineExceeded), http.StatusInternalServerError, "ServiceFailure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _, root := harnessWith(t, func(d iam.Directory) iam.Directory { return stubEnable{d, tc.err} })
			if _, err := f.CreateUser(t.Context(), root.Account, "alice", "/"); err != nil {
				t.Fatal(err)
			}
			has(t, call(t, h, root, sigv4.ServiceIAM, enableForm("alice", "arn:vws:iam::123456789012:mfa/alice-phone")),
				tc.status, `<Code>`+tc.code+`</Code>`)
		})
	}
}

// A caller without iam:EnableMFADevice on the user is AccessDenied and the
// device stays unassigned.
func TestEnableMFADeviceNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	if _, err := f.CreateUser(t.Context(), root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	serial := f.AddTOTPMfaDevice(root.Account, "alice-phone", enableSeed)
	has(t, call(t, h, bob, sigv4.ServiceIAM, enableForm("alice", serial)),
		http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}),
		http.StatusOK, `<MFADevices></MFADevices>`)
}

// AWS validates every member before it authorizes: a caller without
// permission gets 400 ValidationError for a malformed request, and nothing
// is authorized. A code never appears in the message.
func TestEnableMFADeviceValidationPrecedesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	serial := "arn:vws:iam::123456789012:mfa/alice-phone"
	for name, edit := range map[string]func(url.Values){
		"no UserName":     func(v url.Values) { v.Del("UserName") },
		"empty UserName":  func(v url.Values) { v.Set("UserName", "") },
		"bad UserName":    func(v url.Values) { v.Set("UserName", "a b") },
		"no SerialNumber": func(v url.Values) { v.Del("SerialNumber") },
		"short serial":    func(v url.Values) { v.Set("SerialNumber", "short") },
		"no code 1":       func(v url.Values) { v.Del("AuthenticationCode1") },
		"no code 2":       func(v url.Values) { v.Del("AuthenticationCode2") },
		"short code":      func(v url.Values) { v.Set("AuthenticationCode1", "12345") },
		"long code":       func(v url.Values) { v.Set("AuthenticationCode2", "1234567") },
		"letters":         func(v url.Values) { v.Set("AuthenticationCode1", "12a456") },
	} {
		t.Run(name, func(t *testing.T) {
			rec.seen = nil
			form := enableForm("alice", serial)
			edit(form)
			res := call(t, h, bob, sigv4.ServiceIAM, form)
			has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
			for _, k := range []string{"AuthenticationCode1", "AuthenticationCode2"} {
				if c := form.Get(k); c != "" && strings.Contains(res.Body.String(), c) {
					t.Errorf("message echoes %s: %s", k, res.Body.String())
				}
			}
			if len(rec.seen) != 0 {
				t.Errorf("authorized before validation: %v", rec.seen)
			}
		})
	}
	// A parameter the action does not take is rejected.
	form := enableForm("alice", serial)
	form.Set("Marker", "x")
	has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusBadRequest)
}
