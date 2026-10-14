package iamquery

import (
	"net/http"
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
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateLoginProfile"}, "UserName": {"bob"}, "Password": {"x long enough"}, "PasswordResetRequired": {"true"}}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
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
