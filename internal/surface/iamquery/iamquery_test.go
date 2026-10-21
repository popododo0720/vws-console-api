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

func TestUpdateGroup(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateGroup(ctx, root.Account, "dev", "/old/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateGroup(ctx, root.Account, "taken", "/"); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"dev"}, "NewPath": {"/new/"}, "NewGroupName": {"ops"},
	})
	has(t, res, http.StatusOK, `<UpdateGroupResponse>`, `<ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), "UpdateGroupResult") {
		t.Errorf("empty result has an UpdateGroupResult: %s", res.Body.String())
	}
	group, _, err := f.GetGroup(ctx, root.Account, "ops")
	if err != nil || group.Path != "/new/" {
		t.Fatalf("stored group %+v, want path /new/: %v", group, err)
	}
	wantOld := "iam:UpdateGroup arn:vws:iam::123456789012:group/old/dev"
	wantNew := "iam:UpdateGroup arn:vws:iam::123456789012:group/new/ops"
	if len(rec.seen) < 2 || rec.seen[len(rec.seen)-2] != wantOld || rec.seen[len(rec.seen)-1] != wantNew {
		t.Errorf("authorized %v, want last %q then %q", rec.seen, wantOld, wantNew)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"none"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"ops"}, "NewGroupName": {"taken"},
	})
	has(t, res, http.StatusConflict, `<Code>EntityAlreadyExists</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"ops"}, "NewPath": {""},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"ops"}, "NewGroupName": {""},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`, `Value null at`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"ops"}, "NewPath": {"new"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
}

func TestUpdateGroupAuthorizesTheNewARN(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateGroup(ctx, root.Account, "scoped", "/old/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	old := "arn:vws:iam::123456789012:group/old/scoped"
	moved := "arn:vws:iam::123456789012:group/new/scoped"
	allow := func(resources string) string {
		return `{"Statement":[{"Effect":"Allow","Action":"iam:UpdateGroup","Resource":` + resources + `}]}`
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "update", allow(`"`+old+`"`)); err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	res := call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"scoped"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if group, _, err := f.GetGroup(ctx, root.Account, "scoped"); err != nil || group.Path != "/old/" {
		t.Fatalf("denied update changed the group to %+v: %v", group, err)
	}
	both := allow(`["` + old + `","` + moved + `"]`)
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "update", both); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateGroup"}, "GroupName": {"scoped"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusOK, `<UpdateGroupResponse>`, `<ResponseMetadata><RequestId>`)
	if group, _, err := f.GetGroup(ctx, root.Account, "scoped"); err != nil || group.Path != "/new/" {
		t.Fatalf("allowed update left the group at %+v: %v", group, err)
	}
	wantOld := "iam:UpdateGroup " + old
	wantNew := "iam:UpdateGroup " + moved
	if len(rec.seen) < 2 || rec.seen[len(rec.seen)-2] != wantOld || rec.seen[len(rec.seen)-1] != wantNew {
		t.Errorf("authorized %v, want last %q then %q", rec.seen, wantOld, wantNew)
	}
}

func TestUpdateAssumeRolePolicy(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	oldTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}`
	newTrust := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"sts:AssumeRole",` +
		`"Principal":{"AWS":"arn:vws:iam::123456789012:user/bob"}}]}`
	roleIn := iam.RoleInput{Name: "ops", Path: "/", TrustPolicy: oldTrust}
	if _, err := f.CreateRole(ctx, root.Account, roleIn); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"ops"}, "PolicyDocument": {newTrust},
	})
	has(t, res, http.StatusOK, `<UpdateAssumeRolePolicyResponse>`, `<ResponseMetadata><RequestId>`)
	role, err := f.GetRole(ctx, root.Account, "ops")
	if err != nil || role.TrustPolicy != newTrust {
		t.Fatalf("stored trust policy %s, want %s: %v", role.TrustPolicy, newTrust, err)
	}
	want := "iam:UpdateAssumeRolePolicy arn:vws:iam::123456789012:role/ops"
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"ops"}, "PolicyDocument": {"{nope"},
	})
	has(t, res, http.StatusBadRequest, `<Code>MalformedPolicyDocument</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"none"}, "PolicyDocument": {newTrust},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	big := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",` +
		`"Principal":"*","Sid":"` + strings.Repeat("a", 6200) + `"}]}`
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"ops"}, "PolicyDocument": {big},
	})
	has(t, res, http.StatusConflict, `<Code>LimitExceeded</Code>`)
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

func TestUpdateRoleDescription(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "ops", Path: "/", TrustPolicy: trust, Description: "old",
	}); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {"new"},
	})
	has(t, res, http.StatusOK,
		`<UpdateRoleDescriptionResponse><UpdateRoleDescriptionResult><Role>`,
		`<RoleName>ops</RoleName>`, `<Description>new</Description>`,
		`<ResponseMetadata><RequestId>`)
	role, err := f.GetRole(ctx, root.Account, "ops")
	if err != nil || role.Description != "new" {
		t.Fatalf("stored description %q, want new: %v", role.Description, err)
	}
	want := "iam:UpdateRoleDescription arn:vws:iam::123456789012:role/ops"
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {"new"},
	})
	has(t, res, http.StatusOK, `<Description>new</Description>`)

	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "team", Path: "/team/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"team"}, "Description": {"new"},
	})
	has(t, res, http.StatusOK, `<RoleName>team</RoleName>`, `<Path>/team/</Path>`)
	want = "iam:UpdateRoleDescription arn:vws:iam::123456789012:role/team/team"
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}

	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"none"}, "Description": {"new"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	long := strings.Repeat("x", 1001)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {long},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)

	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "svc", Path: iam.ServiceLinkedRolePath + "compute.vws/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"svc"}, "Description": {"new"},
	})
	has(t, res, http.StatusBadRequest, `<Code>UnmodifiableEntity</Code>`)
}
