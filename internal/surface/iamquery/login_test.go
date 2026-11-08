package iamquery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestLoginProfiles(t *testing.T) {
	h, _, rec, root := harness(t)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateUser"}, "UserName": {"bob"}}), http.StatusOK)
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateLoginProfile"}, "UserName": {"bob"}, "Password": {"correct horse 1"}})
	has(t, res, http.StatusOK, `<CreateLoginProfileResult><LoginProfile><UserName>bob</UserName><CreateDate>2026-10-09T10:00:00Z</CreateDate><PasswordResetRequired>false</PasswordResetRequired></LoginProfile></CreateLoginProfileResult>`)
	if strings.Contains(res.Body.String(), "horse") {
		t.Fatal("password echoed")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateLoginProfile"}, "UserName": {"bob"}, "Password": {"correct horse 1"}}), http.StatusConflict, `<Code>EntityAlreadyExists</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetLoginProfile"}, "UserName": {"bob"}}), http.StatusOK, `<GetLoginProfileResult><LoginProfile><UserName>bob</UserName>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"UpdateLoginProfile"}, "UserName": {"bob"}, "Password": {"short"}}), http.StatusBadRequest, `<Code>PasswordPolicyViolation</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"UpdateLoginProfile"}, "UserName": {"bob"}, "Password": {"another pass 2"}}), http.StatusOK, `<UpdateLoginProfileResponse>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"DeleteUser"}, "UserName": {"bob"}}), http.StatusConflict, `<Code>DeleteConflict</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"DeleteLoginProfile"}, "UserName": {"bob"}}), http.StatusOK)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetLoginProfile"}, "UserName": {"bob"}}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	want := "iam:CreateLoginProfile arn:vws:iam::123456789012:user/bob"
	found := false
	for _, s := range rec.seen {
		found = found || s == want
	}
	if !found {
		t.Errorf("never authorized %q: %v", want, rec.seen)
	}
}

// PasswordResetRequired is stored on create, read back by Get and Create,
// and changed by an UpdateLoginProfile that names only it, which keeps the
// password.
func TestPasswordResetRequiredRoundTrips(t *testing.T) {
	h, _, _, root := harness(t)
	// bob is the user of every call; kv are the other members.
	bob := func(action string, kv ...string) *httptest.ResponseRecorder {
		t.Helper()
		v := url.Values{"Action": {action}, "UserName": {"bob"}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return call(t, h, root, sigv4.ServiceIAM, v)
	}
	profile := func(flag string) string {
		t.Helper()
		return `<LoginProfile><UserName>bob</UserName><CreateDate>2026-10-09T10:00:00Z</CreateDate>` +
			`<PasswordResetRequired>` + flag + `</PasswordResetRequired></LoginProfile>`
	}
	const pw, reset = "Password", "PasswordResetRequired"
	const invalid, policy = `<Code>InvalidInput</Code>`, `<Code>PasswordPolicyViolation</Code>`
	has(t, bob("CreateUser"), http.StatusOK)
	has(t, bob("UpdateLoginProfile", reset, "true"), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, bob("CreateLoginProfile", pw, "correct horse 1", reset, "TRUE"), http.StatusBadRequest, invalid)
	has(t, bob("CreateLoginProfile", pw, "correct horse 1", reset, "true"), http.StatusOK, profile("true"))
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("true"))
	has(t, bob("UpdateLoginProfile", reset, "false"), http.StatusOK, `<UpdateLoginProfileResponse>`)
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("false"))
	has(t, bob("UpdateLoginProfile", pw, "another pass 2"), http.StatusOK)
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("false"))
	has(t, bob("UpdateLoginProfile", pw, "third pass 3", reset, "true"), http.StatusOK)
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("true"))
	has(t, bob("UpdateLoginProfile"), http.StatusOK)
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("true"))
	has(t, bob("UpdateLoginProfile", pw, ""), http.StatusBadRequest, `<Code>ValidationError</Code>`, `&#39;password&#39;`)
	has(t, bob("UpdateLoginProfile", reset, "yes"), http.StatusBadRequest, invalid)
	has(t, bob("UpdateLoginProfile", reset, ""), http.StatusBadRequest, invalid)
	has(t, bob("UpdateLoginProfile", pw, "short", reset, "false"), http.StatusBadRequest, policy)
	has(t, bob("GetLoginProfile"), http.StatusOK, profile("true"))
}
