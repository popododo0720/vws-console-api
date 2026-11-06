package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func sessionCredential(t *testing.T, body string) sigv4.Credential {
	t.Helper()
	var got struct {
		AccessKeyID     string `xml:"GetSessionTokenResult>Credentials>AccessKeyId"`
		SecretAccessKey string `xml:"GetSessionTokenResult>Credentials>SecretAccessKey"`
		SessionToken    string `xml:"GetSessionTokenResult>Credentials>SessionToken"`
	}
	if err := xml.Unmarshal([]byte(body), &got); err != nil || got.SessionToken == "" {
		t.Fatalf("credentials in %s: %v", body, err)
	}
	return sigv4.Credential{AccessKey: got.AccessKeyID, Secret: got.SecretAccessKey, SessionToken: got.SessionToken}
}

// GetSessionToken needs no permission, as in AWS, and its credentials act as
// the calling user.
func TestGetSessionToken(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}

	res := call(t, h, bob, sigv4.ServiceSTS, url.Values{"Action": {"GetSessionToken"}})
	has(t, res, http.StatusOK, `<GetSessionTokenResponse><GetSessionTokenResult><Credentials><AccessKeyId>ASIA`,
		`<Expiration>2026-10-09T22:00:00Z</Expiration>`, `<ResponseMetadata><RequestId>`)
	if strings.Contains(strings.Join(rec.seen, "\n"), "sts:GetSessionToken") {
		t.Errorf("GetSessionToken was authorized: %v", rec.seen)
	}
	session := sessionCredential(t, res.Body.String())
	has(t, call(t, h, session, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK,
		`<Arn>arn:aws:iam::123456789012:user/bob</Arn>`)
	has(t, call(t, h, session, sigv4.ServiceSTS, url.Values{"Action": {"GetSessionToken"}}), http.StatusForbidden,
		`<Code>AccessDenied</Code>`, `Cannot call GetSessionToken with session credentials`)

	has(t, call(t, h, root, sigv4.ServiceSTS, url.Values{"Action": {"GetSessionToken"}, "DurationSeconds": {"129600"}}),
		http.StatusOK, `<Expiration>2026-10-09T11:00:00Z</Expiration>`)
	has(t, call(t, h, bob, sigv4.ServiceSTS, url.Values{"Action": {"GetSessionToken"}, "DurationSeconds": {"900"}}),
		http.StatusOK, `<Expiration>2026-10-09T10:15:00Z</Expiration>`)
}

func TestGetSessionTokenWithMFA(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	seed := []byte("12345678901234567890")
	serial := f.AddTOTPMfaDevice(root.Account, "bob-phone", seed)
	if err := f.AssignMfaDevice(root.Account, serial, "bob", now); err != nil {
		t.Fatal(err)
	}
	code := iam.TOTPCode(seed, now)
	form := url.Values{"Action": {"GetSessionToken"}, "SerialNumber": {serial}, "TokenCode": {code}}
	has(t, call(t, h, bob, sigv4.ServiceSTS, form), http.StatusOK, `<SessionToken>`)
	res := call(t, h, bob, sigv4.ServiceSTS, form)
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`, `invalid MFA one time pass code`)
	if strings.Contains(res.Body.String(), code) {
		t.Errorf("the token code is echoed: %s", res.Body.String())
	}
}

func TestGetSessionTokenValidation(t *testing.T) {
	h, _, _, root := harness(t)
	for _, tc := range []struct {
		name   string
		form   url.Values
		status int
		want   []string
	}{
		{
			"duration below 900",
			url.Values{"DurationSeconds": {"899"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `greater than or equal to 900`},
		},
		{
			"duration above 129600",
			url.Values{"DurationSeconds": {"129601"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `less than or equal to 129600`},
		},
		{
			"duration not a number",
			url.Values{"DurationSeconds": {"1h"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`},
		},
		{
			"short serial",
			url.Values{"SerialNumber": {"GAHT1234"}, "TokenCode": {"123456"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `at &#39;serialNumber&#39;`},
		},
		{
			"serial with a space",
			url.Values{"SerialNumber": {"GAHT 12345678"}, "TokenCode": {"123456"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `at &#39;serialNumber&#39;`},
		},
		{
			"five digit code",
			url.Values{"SerialNumber": {"GAHT12345678"}, "TokenCode": {"12345"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `at &#39;tokenCode&#39;`},
		},
		{
			"code with a letter",
			url.Values{"SerialNumber": {"GAHT12345678"}, "TokenCode": {"12345a"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `at &#39;tokenCode&#39;`},
		},
		{
			"serial without a code",
			url.Values{"SerialNumber": {"GAHT12345678"}},
			http.StatusForbidden,
			[]string{`<Code>AccessDenied</Code>`, `must provide both MFA serial number and one time pass code`},
		},
		{
			"code without a serial",
			url.Values{"TokenCode": {"123456"}},
			http.StatusForbidden,
			[]string{`<Code>AccessDenied</Code>`, `must provide both`},
		},
		{
			"unapplied parameter",
			url.Values{"MinimumSessionTokenSize": {"0"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.form.Set("Action", "GetSessionToken")
			has(t, call(t, h, root, sigv4.ServiceSTS, tc.form), tc.status, tc.want...)
		})
	}
}
