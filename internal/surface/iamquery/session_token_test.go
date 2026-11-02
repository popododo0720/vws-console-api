package iamquery

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// sessionTokenAdmin records what GetSessionToken was asked and answers err
// when set; otherwise the fake answers.
type sessionTokenAdmin struct {
	iam.Directory
	err      error
	duration []time.Duration
	mfa      []string
}

func (a *sessionTokenAdmin) GetSessionToken(
	ctx context.Context, caller iam.Principal, d time.Duration, serial, code string,
) (iam.Key, error) {
	a.duration = append(a.duration, d)
	a.mfa = append(a.mfa, serial+"|"+code)
	if a.err != nil {
		return iam.Key{}, a.err
	}
	return a.Directory.GetSessionToken(ctx, caller, d, "", "")
}

func sessionTokenHarness(t *testing.T) (http.Handler, *iam.Fake, *recorder, sigv4.Credential, *sessionTokenAdmin) {
	t.Helper()
	var a *sessionTokenAdmin
	h, f, rec, root := harnessWith(t, func(d iam.Directory) iam.Directory {
		a = &sessionTokenAdmin{Directory: d}
		return a
	})
	return h, f, rec, root, a
}

func sts(form url.Values) url.Values {
	form.Set("Action", "GetSessionToken")
	return form
}

// GetSessionToken answers the AWS shape for an IAM user and the root user,
// with the AWS duration default and bounds, and the credentials it returns
// authenticate as the caller.
func TestGetSessionTokenShapeAndDuration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		asRoot   bool
		duration string
		sent     time.Duration
		expires  string
	}{
		{"user default is 12h", false, "", 0, "2026-10-09T22:00:00Z"},
		{"user minimum 900s", false, "900", 900 * time.Second, "2026-10-09T10:15:00Z"},
		{"user maximum 36h", false, "129600", 129600 * time.Second, "2026-10-10T22:00:00Z"},
		{"root default is 1h", true, "", time.Hour, "2026-10-09T11:00:00Z"},
		{"root above 1h gets 1h", true, "129600", time.Hour, "2026-10-09T11:00:00Z"},
		{"root below 1h keeps it", true, "1800", 30 * time.Minute, "2026-10-09T10:30:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _, root, a := sessionTokenHarness(t)
			cred, arn := root, "arn:aws:iam::123456789012:root"
			if !tc.asRoot {
				cred, arn = callerWithoutPermissions(t, f, root), "arn:aws:iam::123456789012:user/bob"
			}
			form := url.Values{}
			if tc.duration != "" {
				form.Set("DurationSeconds", tc.duration)
			}
			res := call(t, h, cred, sigv4.ServiceSTS, sts(form))
			has(t, res, http.StatusOK,
				`<GetSessionTokenResponse><GetSessionTokenResult><Credentials><AccessKeyId>ASIA`,
				`</AccessKeyId><SecretAccessKey>`, `</SecretAccessKey><SessionToken>`,
				`</SessionToken><Expiration>`+tc.expires+`</Expiration></Credentials></GetSessionTokenResult>`,
				`<ResponseMetadata><RequestId>`, `</ResponseMetadata></GetSessionTokenResponse>`)
			if len(a.duration) != 1 || a.duration[0] != tc.sent {
				t.Errorf("backend asked for %v, want %v", a.duration, tc.sent)
			}
			issued := sigv4.Credential{
				AccessKey:    between(res.Body.String(), "<AccessKeyId>", "</AccessKeyId>"),
				Secret:       between(res.Body.String(), "<SecretAccessKey>", "</SecretAccessKey>"),
				SessionToken: between(res.Body.String(), "<SessionToken>", "</SessionToken>"),
			}
			has(t, call(t, h, issued, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK,
				`<Arn>`+arn+`</Arn>`)
		})
	}
}

func between(s, open, closing string) string {
	_, rest, _ := strings.Cut(s, open)
	v, _, _ := strings.Cut(rest, closing)
	return v
}

// AWS requires no permission for GetSessionToken and ignores
// sts:GetSessionToken in policies, so it never goes through Authorize: a
// user with no policy, or with an explicit Deny on it, still gets
// credentials. An unsigned or badly signed request does not.
func TestGetSessionTokenSkipsAuthorizeButNotAuthentication(t *testing.T) {
	h, f, rec, root, _ := sessionTokenHarness(t)
	bob := callerWithoutPermissions(t, f, root)
	has(t, call(t, h, bob, sigv4.ServiceSTS, sts(url.Values{})), http.StatusOK, `<GetSessionTokenResult>`)
	ctx := t.Context()
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "deny",
		`{"Statement":[{"Effect":"Deny","Action":"sts:GetSessionToken","Resource":"*"}]}`,
		backendtest.EntityGrant(ctx, t, f, root.Account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceSTS, sts(url.Values{})), http.StatusOK, `<GetSessionTokenResult>`)
	for _, s := range rec.seen {
		if strings.HasPrefix(s, "sts:GetSessionToken") {
			t.Errorf("GetSessionToken went through Authorize: %v", rec.seen)
		}
	}
	has(t, call(t, h, sigv4.Credential{AccessKey: bob.AccessKey, Secret: "wrong"}, sigv4.ServiceSTS, sts(url.Values{})),
		http.StatusForbidden, `<Code>SignatureDoesNotMatch</Code>`)
	// Signed for IAM instead of STS, the action does not exist.
	has(t, call(t, h, bob, sigv4.ServiceIAM, sts(url.Values{})), http.StatusBadRequest, `<Code>InvalidAction</Code>`)
}

// Temporary credentials, from AssumeRole or from GetSessionToken itself,
// are AccessDenied with the AWS message, before the backend is called.
func TestGetSessionTokenRefusesSessionCredentials(t *testing.T) {
	h, f, _, root, a := sessionTokenHarness(t)
	ctx := t.Context()
	u, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{Name: "ops", Path: "/", TrustPolicy: trust}); err != nil {
		t.Fatal(err)
	}
	bob := iam.Principal{Account: root.Account, ARN: u.ARN}
	assumed, err := f.AssumeRole(ctx, bob, "arn:vws:iam::123456789012:role/ops", "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.GetSessionToken(ctx, bob, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]iam.Key{"assumed role": assumed.Key, "session token": session} {
		cred := sigv4.Credential{AccessKey: k.AccessKey, Secret: k.Secret, SessionToken: k.SessionToken}
		has(t, call(t, h, cred, sigv4.ServiceSTS, sts(url.Values{"DurationSeconds": {"3600"}})), http.StatusForbidden,
			`<Type>Sender</Type><Code>AccessDenied</Code>`,
			`<Message>Cannot call GetSessionToken with session credentials</Message>`)
		if len(a.duration) != 0 {
			t.Errorf("%s: the backend was called %d times", name, len(a.duration))
		}
	}
}

// Each input constraint of the AWS reference is a 400 ValidationError with
// the AWS message; several are reported together. The token code is never
// echoed. Nothing reaches the backend.
func TestGetSessionTokenValidation(t *testing.T) {
	const (
		pre = "1 validation error detected: "
		dur = "' at 'durationSeconds' failed to satisfy constraint: Member must have value "
		ser = "' at 'serialNumber' failed to satisfy constraint: Member must "
		tok = "Value at 'tokenCode' failed to satisfy constraint: Member must "
	)
	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{
			"duration below 900",
			url.Values{"DurationSeconds": {"899"}},
			pre + "Value '899" + dur + "greater than or equal to 900",
		},
		{
			"duration above 129600",
			url.Values{"DurationSeconds": {"129601"}},
			pre + "Value '129601" + dur + "less than or equal to 129600",
		},
		{
			"duration not a number",
			url.Values{"DurationSeconds": {"soon"}},
			pre + "Value 'soon" + dur + "greater than or equal to 900",
		},
		{
			"serial too short",
			url.Values{"SerialNumber": {"GAHT1234"}},
			pre + "Value 'GAHT1234" + ser + "have length greater than or equal to 9",
		},
		{
			"serial too long",
			url.Values{"SerialNumber": {strings.Repeat("a", 257)}},
			ser + "have length less than or equal to 256",
		},
		{
			"serial pattern",
			url.Values{"SerialNumber": {"GAHT 12345678"}},
			ser + `satisfy regular expression pattern: [\w+=/:,.@-]*`,
		},
		{
			"code too short",
			url.Values{"TokenCode": {"12345"}},
			pre + tok + "have length greater than or equal to 6",
		},
		{"code too long", url.Values{"TokenCode": {"1234567"}}, pre + tok + "have length less than or equal to 6"},
		{
			"code not digits",
			url.Values{"TokenCode": {"12a456"}},
			pre + tok + `satisfy regular expression pattern: [\d]*`,
		},
		{
			"two errors",
			url.Values{"DurationSeconds": {"1"}, "TokenCode": {"12a456"}},
			"2 validation errors detected: Value '1" + dur + "greater than or equal to 900; " +
				tok + `satisfy regular expression pattern: [\d]*`,
		},
		{
			"unsupported parameter",
			url.Values{"MinimumSessionTokenSize": {"0"}},
			"Parameter MinimumSessionTokenSize is not supported",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _, root, a := sessionTokenHarness(t)
			bob := callerWithoutPermissions(t, f, root)
			res := call(t, h, bob, sigv4.ServiceSTS, sts(tc.form))
			has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`, xmlEscape(tc.want))
			if code := tc.form.Get("TokenCode"); code != "" && strings.Contains(res.Body.String(), code) {
				t.Errorf("token code echoed: %s", res.Body)
			}
			if len(a.duration) != 0 {
				t.Errorf("the backend was called %d times", len(a.duration))
			}
		})
	}
}

// Backend failures keep their AWS code and status: RegionDisabledException
// 403, AccessDenied 403 (a wrong MFA code), ValidationError 400,
// ServiceUnavailable 503, and ServiceFailure 500 without the cause. The MFA
// pair reaches the backend as sent.
func TestGetSessionTokenErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{
			"region disabled", &resource.Error{
				Code: resource.CodePermissionDenied, Field: iam.RegionDisabled,
				Message: "STS is not activated in this region for account:123456789012.",
			}, http.StatusForbidden, "RegionDisabledException",
		},
		{
			"wrong MFA code", resource.Denied("MultiFactorAuthentication failed with invalid MFA one time pass code."),
			http.StatusForbidden, "AccessDenied",
		},
		{
			"backend validation", resource.Invalid("durationSeconds", "DurationSeconds is outside the allowed range."),
			http.StatusBadRequest, "ValidationError",
		},
		{
			"unavailable", &resource.Error{Code: resource.CodeUnavailable, Message: "try again"},
			http.StatusServiceUnavailable, "ServiceUnavailable",
		},
		{"internal", errors.New("vws-iam: Internal secret-cause"), http.StatusInternalServerError, "ServiceFailure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _, root, a := sessionTokenHarness(t)
			a.err = tc.err
			bob := callerWithoutPermissions(t, f, root)
			res := call(t, h, bob, sigv4.ServiceSTS, sts(url.Values{
				"SerialNumber": {"arn:aws:iam::123456789012:mfa/bob"}, "TokenCode": {"654321"},
			}))
			has(t, res, tc.status, `<Code>`+tc.code+`</Code>`)
			if strings.Contains(res.Body.String(), "secret-cause") || strings.Contains(res.Body.String(), "654321") {
				t.Errorf("leaked: %s", res.Body)
			}
			if len(a.mfa) != 1 || a.mfa[0] != "arn:aws:iam::123456789012:mfa/bob|654321" {
				t.Errorf("MFA sent %v", a.mfa)
			}
		})
	}
}

// The fake refuses any MFA code, as vws-iam does without an MFA verifier,
// and the surface answers AccessDenied without the code.
func TestGetSessionTokenFakeRefusesMFA(t *testing.T) {
	h, f, _, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	res := call(t, h, bob, sigv4.ServiceSTS, sts(url.Values{
		"SerialNumber": {"arn:aws:iam::123456789012:mfa/bob"}, "TokenCode": {"123456"},
	}))
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if strings.Contains(res.Body.String(), "123456<") {
		t.Errorf("token code echoed: %s", res.Body)
	}
}

// Without an Admin only GetCallerIdentity is served.
func TestGetSessionTokenNeedsAdmin(t *testing.T) {
	_, _, rec, root := harness(t)
	verifier := sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceSTS, Region: resource.RegionName,
		Now: func() time.Time { return now }, Auth: iam.Authenticator(rec),
	})
	h := New(Config{Authorizer: rec, STS: verifier})
	has(t, call(t, h, root, sigv4.ServiceSTS, sts(url.Values{})), http.StatusBadRequest, `<Code>InvalidAction</Code>`)
}
