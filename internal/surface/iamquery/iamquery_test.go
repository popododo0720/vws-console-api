package iamquery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var now = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

type recorder struct {
	iam.Client
	seen []string
}

func (r *recorder) Authorize(ctx context.Context, req iam.Request) (iam.Decision, error) {
	r.seen = append(r.seen, req.Action+" "+req.Resource)
	return r.Client.Authorize(ctx, req)
}

func harness(t *testing.T) (http.Handler, *iam.Fake, *recorder, sigv4.Credential) {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	f := iam.NewFake()
	f.Now = func() time.Time { return now }
	rec := &recorder{Client: iam.WithRoot(iam.NewStatic("AKIDEXAMPLE", "secret", account), f)}
	verifier := func(s sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{Service: s, Region: resource.RegionName, Now: func() time.Time { return now }, Auth: iam.Authenticator(rec)})
	}
	h := New(Config{Admin: f, Authorizer: rec, IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS)})
	return h, f, rec, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
}

func call(t *testing.T, h http.Handler, cred sigv4.Credential, service sigv4.Service, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if form.Get("Version") == "" {
		form.Set("Version", map[sigv4.Service]string{sigv4.ServiceIAM: IAMVersion, sigv4.ServiceSTS: STSVersion}[service])
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8084/", strings.NewReader(form.Encode()))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := sigv4.Sign(req, cred, service, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func has(t *testing.T, res *httptest.ResponseRecorder, status int, parts ...string) {
	t.Helper()
	body := res.Body.String()
	if res.Code != status {
		t.Errorf("status %d, want %d: %s", res.Code, status, body)
		return
	}
	for _, p := range parts {
		if !strings.Contains(body, p) {
			t.Errorf("missing %q in %s", p, body)
		}
	}
}

func TestIAMResponseAndErrorShapes(t *testing.T) {
	h, _, rec, root := harness(t)
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateUser"}, "UserName": {"bob"}, "Path": {"/eng/"}})
	has(t, res, http.StatusOK,
		`<CreateUserResponse>`,
		`<CreateUserResult><User><Path>/eng/</Path><UserName>bob</UserName><UserId>AIDA`,
		`<Arn>arn:vws:iam::123456789012:user/eng/bob</Arn><CreateDate>2026-10-09T10:00:00Z</CreateDate></User></CreateUserResult>`,
		`<ResponseMetadata><RequestId>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetUser"}, "UserName": {"nobody"}})
	has(t, res, http.StatusNotFound, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateUser"}, "UserName": {"bob"}})
	has(t, res, http.StatusConflict, `<Code>EntityAlreadyExists</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreatePolicy"}, "PolicyName": {"p"}, "PolicyDocument": {"{nope"}})
	has(t, res, http.StatusBadRequest, `<Code>MalformedPolicyDocument</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"FlyToTheMoon"}})
	has(t, res, http.StatusBadRequest, `<Code>InvalidAction</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateUser"}, "UserName": {"tagged"}, "Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"}})
	has(t, res, http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	if want := "iam:CreateUser arn:vws:iam::123456789012:user/eng/bob"; len(rec.seen) == 0 || rec.seen[0] != want {
		t.Errorf("authorized %v, want first %q", rec.seen, want)
	}
}

func TestPolicyDocumentsAreURLEncoded(t *testing.T) {
	h, _, _, root := harness(t)
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreatePolicy"}, "PolicyName": {"d"}, "PolicyDocument": {doc}})
	has(t, res, http.StatusOK, `<Arn>arn:vws:iam::123456789012:policy/d</Arn>`, `<DefaultVersionId>v1</DefaultVersionId>`, `<AttachmentCount>0</AttachmentCount>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetPolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/d"}, "VersionId": {"v1"}})
	has(t, res, http.StatusOK, `<Document>`+strings.ReplaceAll(url.QueryEscape(doc), "+", "%20")+`</Document>`, `<IsDefaultVersion>true</IsDefaultVersion>`)
}

func TestLimitedUserAndSTS(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	u, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "p", `{"Statement":[{"Effect":"Allow","Action":["iam:GetUser","sts:GetCallerIdentity","sts:AssumeRole"],"Resource":"*"}]}`); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"GetUser"}, "UserName": {"bob"}}), http.StatusOK, `<UserName>bob</UserName>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListUsers"}}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK,
		`<GetCallerIdentityResponse><GetCallerIdentityResult>`,
		`<Arn>`+u.ARN+`</Arn>`, `<UserId>`+u.ID+`</UserId>`, `<Account>123456789012</Account>`)
	// GetUser without UserName names the caller, as in AWS.
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"GetUser"}}), http.StatusOK, `<UserName>bob</UserName>`)
	has(t, call(t, h, root, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK, `<Arn>arn:vws:iam::123456789012:root</Arn>`)

	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + u.ARN + `"}}]}`
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"CreateRole"}, "RoleName": {"ops"}, "AssumeRolePolicyDocument": {trust}}),
		http.StatusOK, `<RoleName>ops</RoleName>`, `<AssumeRolePolicyDocument>`, `<MaxSessionDuration>3600</MaxSessionDuration>`)
	res := call(t, h, bob, sigv4.ServiceSTS, url.Values{"Action": {"AssumeRole"}, "RoleArn": {"arn:vws:iam::123456789012:role/ops"}, "RoleSessionName": {"s1"}, "DurationSeconds": {"900"}})
	has(t, res, http.StatusOK, `<AssumeRoleResult><Credentials><AccessKeyId>ASIA`, `<SessionToken>`, `<Expiration>2026-10-09T10:15:00Z</Expiration>`,
		`<AssumedRoleUser><AssumedRoleId>AROA`, `<Arn>arn:vws:sts::123456789012:assumed-role/ops/s1</Arn>`)
	has(t, call(t, h, bob, sigv4.ServiceSTS, url.Values{"Action": {"AssumeRole"}, "RoleArn": {"arn:vws:iam::123456789012:role/ops"}, "RoleSessionName": {"s1"}, "DurationSeconds": {"60"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	unknown := sigv4.Credential{AccessKey: "AKIANOSUCHKEY0000000", Secret: "x"}
	has(t, call(t, h, unknown, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusForbidden,
		`<ErrorResponse><Error><Type>Sender</Type>`, `<Code>InvalidClientTokenId</Code>`)
	wrongSecret := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: "nope"}
	has(t, call(t, h, wrongSecret, sigv4.ServiceIAM, url.Values{"Action": {"GetUser"}}), http.StatusForbidden, `<Code>SignatureDoesNotMatch</Code>`)
	for _, want := range []string{"iam:GetUser arn:vws:iam::123456789012:user/bob", "iam:ListUsers *", "sts:AssumeRole arn:vws:iam::123456789012:role/ops"} {
		if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
			t.Errorf("not authorized: %q in %v", want, rec.seen)
		}
	}
}

// GetCallerIdentity needs no permission, as in AWS, but still needs a valid
// signature.
func TestGetCallerIdentitySkipsAuthorizeButNotAuthentication(t *testing.T) {
	h, f, rec, root := harness(t)
	u, err := f.CreateUser(t.Context(), root.Account, "nobody", "/")
	if err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(t.Context(), root.Account, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	bare := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	has(t, call(t, h, bare, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK, `<Arn>`+u.ARN+`</Arn>`)
	for _, s := range rec.seen {
		if strings.HasPrefix(s, "sts:GetCallerIdentity") {
			t.Errorf("GetCallerIdentity went through Authorize: %v", rec.seen)
		}
	}
	has(t, call(t, h, sigv4.Credential{AccessKey: k.AccessKeyID, Secret: "wrong"}, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}),
		http.StatusForbidden, `<Code>SignatureDoesNotMatch</Code>`)
	unsigned := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8084/",
		strings.NewReader("Action=GetCallerIdentity&Version="+STSVersion))
	unsigned.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, unsigned)
	has(t, res, http.StatusForbidden, `<Code>MissingAuthenticationToken</Code>`)
}
