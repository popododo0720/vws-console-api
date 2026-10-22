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

// vanishedUserAdmin serves the user for the action's first ARN check and
// reports it missing for the snapshot read, like a delete between the two.
type vanishedUserAdmin struct {
	iam.Admin
	calls int
}

func (a *vanishedUserAdmin) GetUser(ctx context.Context, account resource.AccountID, name string) (iam.User, error) {
	a.calls++
	if a.calls > 1 {
		return iam.User{}, &resource.Error{Code: resource.CodeNotFound, Message: "The user cannot be found."}
	}
	return a.Admin.GetUser(ctx, account, name)
}

// noARNAdmin finds a key but gives its owner no ARN, which the surface must
// reject instead of authorizing on "*".
type noARNAdmin struct{ iam.Admin }

func (a noARNAdmin) GetAccessKeyLastUsed(
	_ context.Context, _ resource.AccountID, _ string,
) (iam.AccessKeyLastUsed, error) {
	return iam.AccessKeyLastUsed{UserName: "bob"}, nil
}

func harness(t *testing.T) (http.Handler, *iam.Fake, *recorder, sigv4.Credential) {
	return harnessWith(t, nil)
}

// harnessWith lets a test replace the Admin the surface calls while the same
// fake stays the authorizer.
func harnessWith(t *testing.T, wrap func(iam.Admin) iam.Admin) (http.Handler, *iam.Fake, *recorder, sigv4.Credential) {
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
	var admin iam.Admin = f
	if wrap != nil {
		admin = wrap(f)
	}
	h := New(Config{Admin: admin, Authorizer: rec, IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS)})
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

func TestUpdateUser(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/old/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "taken", "/"); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"bob"}, "NewPath": {"/new/"}, "NewUserName": {"robert"},
	})
	has(t, res, http.StatusOK, `<UpdateUserResponse>`, `<ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), "UpdateUserResult") {
		t.Errorf("empty result has an UpdateUserResult: %s", res.Body.String())
	}
	u, err := f.GetUser(ctx, root.Account, "robert")
	if err != nil || u.Path != "/new/" || u.ARN != "arn:vws:iam::123456789012:user/new/robert" {
		t.Fatalf("stored user %+v: %v", u, err)
	}
	wantOld := "iam:UpdateUser arn:vws:iam::123456789012:user/old/bob"
	wantNew := "iam:UpdateUser arn:vws:iam::123456789012:user/new/robert"
	if len(rec.seen) < 2 || rec.seen[len(rec.seen)-2] != wantOld || rec.seen[len(rec.seen)-1] != wantNew {
		t.Errorf("authorized %v, want last %q then %q", rec.seen, wantOld, wantNew)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"none"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"robert"}, "NewUserName": {"taken"},
	})
	has(t, res, http.StatusConflict, `<Code>EntityAlreadyExists</Code>`)
	for _, form := range []url.Values{
		{"Action": {"UpdateUser"}, "UserName": {"robert"}, "NewPath": {""}},
		{"Action": {"UpdateUser"}, "UserName": {"robert"}, "NewUserName": {""}},
		{"Action": {"UpdateUser"}, "NewPath": {"/new/"}},
		{"Action": {"UpdateUser"}, "UserName": {"robert"}, "NewPath": {"new"}},
	} {
		res = call(t, h, root, sigv4.ServiceIAM, form)
		has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
}

// TestUpdateUserMissingSnapshotIsNoSuchEntity pins the snapshot rule. A user
// that vanishes between the action's first ARN check and the snapshot read
// must not reach UpdateUser with an empty expected ARN, because a user
// recreated under the same name would then move without authorization.
func TestUpdateUserMissingSnapshotIsNoSuchEntity(t *testing.T) {
	h, f, _, root := harnessWith(t, func(admin iam.Admin) iam.Admin {
		return &vanishedUserAdmin{Admin: admin}
	})
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/old/"); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"bob"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	if u, err := f.GetUser(ctx, root.Account, "bob"); err != nil || u.Path != "/old/" {
		t.Errorf("a missing snapshot moved the user to %+v: %v", u, err)
	}
}

func TestUpdateUserAuthorizesTheNewARN(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "scoped", "/old/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	old := "arn:vws:iam::123456789012:user/old/scoped"
	moved := "arn:vws:iam::123456789012:user/new/scoped"
	allow := func(resources string) string {
		return `{"Statement":[{"Effect":"Allow","Action":"iam:UpdateUser","Resource":` + resources + `}]}`
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "update", allow(`"`+old+`"`)); err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	res := call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"scoped"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if u, err := f.GetUser(ctx, root.Account, "scoped"); err != nil || u.Path != "/old/" {
		t.Fatalf("denied update changed the user to %+v: %v", u, err)
	}
	both := allow(`["` + old + `","` + moved + `"]`)
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "update", both); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateUser"}, "UserName": {"scoped"}, "NewPath": {"/new/"},
	})
	has(t, res, http.StatusOK, `<UpdateUserResponse>`, `<ResponseMetadata><RequestId>`)
	if u, err := f.GetUser(ctx, root.Account, "scoped"); err != nil || u.Path != "/new/" {
		t.Fatalf("allowed update left the user at %+v: %v", u, err)
	}
	wantOld := "iam:UpdateUser " + old
	wantNew := "iam:UpdateUser " + moved
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

func TestCreatePolicyVersion(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	newDocument := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:DeleteVpc","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {newDocument}, "SetAsDefault": {"true"},
	})
	has(t, res, http.StatusOK,
		`<CreatePolicyVersionResponse>`,
		`<CreatePolicyVersionResult><PolicyVersion><VersionId>v2</VersionId>`+
			`<IsDefaultVersion>true</IsDefaultVersion><CreateDate>2026-10-09T10:00:00Z</CreateDate>`+
			`</PolicyVersion></CreatePolicyVersionResult>`,
		`<ResponseMetadata><RequestId>`)
	// The create result carries no document.
	if strings.Contains(res.Body.String(), "<Document>") {
		t.Errorf("create result carries a document: %s", res.Body.String())
	}
	want := "iam:CreatePolicyVersion " + p.ARN
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	page, err := f.ListPolicyVersions(ctx, root.Account, p.ARN, "", 0)
	if err != nil || len(page.Versions) != 2 {
		t.Fatalf("versions %+v: %v", page, err)
	}
	if !page.Versions[1].IsDefaultVersion || page.Versions[0].IsDefaultVersion {
		t.Errorf("versions %+v, want v2 default", page.Versions)
	}
	// The policy now reports the new default version.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetPolicy"}, "PolicyArn": {p.ARN},
	}), http.StatusOK, `<DefaultVersionId>v2</DefaultVersionId>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v1"},
	}), http.StatusOK, `<VersionId>v1</VersionId>`, `<IsDefaultVersion>false</IsDefaultVersion>`)
	// v2 is readable and carries its own document.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v2"},
	}), http.StatusOK, `<Document>`+policyDoc(newDocument)+`</Document>`,
		`<VersionId>v2</VersionId>`, `<IsDefaultVersion>true</IsDefaultVersion>`)
	// SetAsDefault is optional and false when omitted.
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document},
	})
	has(t, res, http.StatusOK, `<VersionId>v3</VersionId>`, `<IsDefaultVersion>false</IsDefaultVersion>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/none"},
		"PolicyDocument": {document},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {"{not json"},
	}), http.StatusBadRequest, `<Code>MalformedPolicyDocument</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document}, "SetAsDefault": {"yes"},
	}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN},
	}), http.StatusBadRequest, `<Code>ValidationError</Code>`, `Value null at`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {"not-an-arn"}, "PolicyDocument": {document},
	}), http.StatusBadRequest, `<Code>ValidationError</Code>`, `is not valid`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document}, "PathPrefix": {"/"},
	}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	// The policy keeps five versions, so the sixth is LimitExceeded.
	for _, want := range []string{"v4", "v5"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document},
		}), http.StatusOK, `<VersionId>`+want+`</VersionId>`)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document},
	}), http.StatusConflict, `<Code>LimitExceeded</Code>`)
}

func TestCreatePolicyVersionAuthorizes(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/team/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	allow := `{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicyVersion","Resource":"` + p.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allow); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/admin/versioned"},
		"PolicyDocument": {document},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"CreatePolicyVersion"}, "PolicyArn": {p.ARN}, "PolicyDocument": {document},
	}), http.StatusOK, `<CreatePolicyVersionResponse>`)
}

func TestSetDefaultPolicyVersion(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusOK, `<SetDefaultPolicyVersionResponse>`, `<ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), "SetDefaultPolicyVersionResult") {
		t.Errorf("empty result has a SetDefaultPolicyVersionResult: %s", res.Body.String())
	}
	want := "iam:SetDefaultPolicyVersion " + p.ARN
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	// A well-formed version that does not exist is NoSuchEntity.
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v2"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`, `Policy version v2 does not exist or is not attachable.`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/none"}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	// A value outside the AWS VersionId pattern is InvalidInput.
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"latest"},
	})
	has(t, res, http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {p.ARN},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`, `Value null at`)
}

func TestSetDefaultPolicyVersionAuthorizes(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	allow := `{"Statement":[{"Effect":"Allow","Action":"iam:SetDefaultPolicyVersion","Resource":"` + p.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allow); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/other"}, "VersionId": {"v1"},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"SetDefaultPolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v1"},
	}), http.StatusOK, `<SetDefaultPolicyVersionResponse>`)
}

func TestDeletePolicyVersion(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "d", "/", doc, "")
	if err != nil {
		t.Fatal(err)
	}
	authorized := func(want string) {
		t.Helper()
		if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
			t.Errorf("authorized %v, want last %q", rec.seen, want)
		}
	}
	want := "iam:DeletePolicyVersion " + p.ARN
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusConflict, `<Code>DeleteConflict</Code>`)
	authorized(want)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"v2"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	authorized(want)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {p.ARN}, "VersionId": {"1"},
	})
	has(t, res, http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	authorized(want)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {"not-an-arn"}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	authorized("iam:DeletePolicyVersion not-an-arn")
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/none"}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	authorized("iam:DeletePolicyVersion arn:vws:iam::123456789012:policy/none")
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "VersionId": {"v1"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
}

// versionDeleter succeeds without the fake, which stores only the default
// version, so the success response needs a backend that can delete one.
type versionDeleter struct {
	iam.Admin
	deleted []string
}

func (d *versionDeleter) DeletePolicyVersion(_ context.Context, _ resource.AccountID, arn, versionID string) error {
	d.deleted = append(d.deleted, arn+" "+versionID)
	return nil
}

func TestDeletePolicyVersionSuccess(t *testing.T) {
	admin := &versionDeleter{}
	h, _, _, root := harnessWith(t, func(base iam.Admin) iam.Admin {
		admin.Admin = base
		return admin
	})
	const arn = "arn:vws:iam::123456789012:policy/eng/d"
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeletePolicyVersion"}, "PolicyArn": {arn}, "VersionId": {"v2"},
	})
	has(t, res, http.StatusOK, `<DeletePolicyVersionResponse>`, `<ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), "DeletePolicyVersionResult") {
		t.Errorf("empty result has a DeletePolicyVersionResult: %s", res.Body.String())
	}
	if len(admin.deleted) != 1 || admin.deleted[0] != arn+" v2" {
		t.Errorf("deleted %v, want %q", admin.deleted, arn+" v2")
	}
}

func TestListPolicyVersions(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {p.ARN},
	})
	has(t, res, http.StatusOK,
		`<ListPolicyVersionsResponse>`,
		`<ListPolicyVersionsResult><Versions><member><VersionId>v1</VersionId>`+
			`<IsDefaultVersion>true</IsDefaultVersion><CreateDate>2026-10-09T10:00:00Z</CreateDate>`+
			`</member></Versions><IsTruncated>false</IsTruncated></ListPolicyVersionsResult>`,
		`<ResponseMetadata><RequestId>`)
	// AWS leaves the document out of a version listing.
	if strings.Contains(res.Body.String(), "<Document>") {
		t.Errorf("version listing carries a document: %s", res.Body.String())
	}
	want := "iam:ListPolicyVersions " + p.ARN
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/none"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListPolicyVersions"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`, `Value null at`)
	// A Marker outside the AWS character range is InvalidInput.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {p.ARN}, "Marker": {"\x01"},
	}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	// PathPrefix is not an input of this action.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {p.ARN}, "PathPrefix": {"/"},
	}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	for _, maxItems := range []string{"0", "1001", "many"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"ListPolicyVersions"}, "PolicyArn": {p.ARN}, "MaxItems": {maxItems},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
}

func TestListPolicyVersionsAuthorizes(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "versioned", "/", document, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	allow := `{"Statement":[{"Effect":"Allow","Action":"iam:ListPolicyVersions","Resource":"` + p.ARN + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allow); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {"arn:vws:iam::123456789012:policy/other"},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyVersions"}, "PolicyArn": {p.ARN},
	}), http.StatusOK, `<ListPolicyVersionsResponse>`)
}

func TestGetAccessKeyLastUsed(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	bob, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	used, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {fresh.AccessKeyID},
	})
	has(t, res, http.StatusOK,
		`<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult>`,
		`<AccessKeyLastUsed><ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed><UserName>bob</UserName>`)
	if strings.Contains(res.Body.String(), "LastUsedDate") {
		t.Errorf("unused key has a LastUsedDate: %s", res.Body.String())
	}
	bobCred := sigv4.Credential{AccessKey: used.AccessKeyID, Secret: used.Secret}
	has(t, call(t, h, bobCred, sigv4.ServiceSTS, url.Values{"Action": {"GetCallerIdentity"}}), http.StatusOK)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {used.AccessKeyID},
	})
	has(t, res, http.StatusOK,
		`<AccessKeyLastUsed><LastUsedDate>2026-10-09T10:00:00Z</LastUsedDate>`,
		`<ServiceName>sts</ServiceName><Region>vws-1</Region></AccessKeyLastUsed>`,
		`<UserName>bob</UserName>`)
	if strings.Contains(res.Body.String(), "Secret") {
		t.Errorf("response carries a secret: %s", res.Body.String())
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {"AKIANOSUCHKEY0000000"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	for _, id := range []string{"short", ""} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {id},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}

	// A limited user may read only the key whose owner ARN its policy names.
	if _, err := f.CreateUser(ctx, root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "carol", "/"); err != nil {
		t.Fatal(err)
	}
	aliceKey, err := f.CreateAccessKey(ctx, root.Account, "alice")
	if err != nil {
		t.Fatal(err)
	}
	carolKey, err := f.CreateAccessKey(ctx, root.Account, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "alice", "lastused",
		`{"Statement":[{"Effect":"Allow","Action":"iam:GetAccessKeyLastUsed","Resource":"`+bob.ARN+`"}]}`); err != nil {
		t.Fatal(err)
	}
	alice := sigv4.Credential{AccessKey: aliceKey.AccessKeyID, Secret: aliceKey.Secret}
	has(t, call(t, h, alice, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {used.AccessKeyID},
	}), http.StatusOK, `<UserName>bob</UserName>`)
	has(t, call(t, h, alice, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {carolKey.AccessKeyID},
	}), http.StatusForbidden, `<Code>AccessDenied</Code>`)

	want := "iam:GetAccessKeyLastUsed arn:vws:iam::123456789012:user/bob"
	if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
		t.Errorf("not authorized: %q in %v", want, rec.seen)
	}
}

func TestGetAccessKeyLastUsedFailsClosedWithoutOwnerARN(t *testing.T) {
	h, _, _, root := harnessWith(t, func(a iam.Admin) iam.Admin { return noARNAdmin{a} })
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetAccessKeyLastUsed"}, "AccessKeyId": {"AKIAABCDEFGHIJKLMNOP"},
	}), http.StatusInternalServerError, `<Code>ServiceFailure</Code>`)
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
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {"\u0080"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	wide := strings.Repeat("\u00ff", iam.MaxRoleDescription)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {wide},
	})
	has(t, res, http.StatusOK, "<Description>"+wide+"</Description>")
	if stored, err := f.GetRole(ctx, root.Account, "ops"); err != nil || stored.Description != wide {
		t.Fatalf("1000-character description stored as %q: %v", stored.Description, err)
	}

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

func TestUpdateRole(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "ops", Path: "/", TrustPolicy: trust, Description: "old", MaxSessionDuration: 7200,
	}); err != nil {
		t.Fatal(err)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {"new"},
	})
	has(t, res, http.StatusOK,
		`<UpdateRoleResponse>`, `<UpdateRoleResult>`, `<ResponseMetadata><RequestId>`)
	want := "iam:UpdateRole arn:vws:iam::123456789012:role/ops"
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {"new"},
	})
	has(t, res, http.StatusOK, `<UpdateRoleResult>`)
	role, err := f.GetRole(ctx, root.Account, "ops")
	if err != nil || role.Description != "new" || role.MaxSessionDuration != 7200 {
		t.Fatalf("stored role %+v, want new description and 7200: %v", role, err)
	}

	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "MaxSessionDuration": {"43200"},
	})
	has(t, res, http.StatusOK, `<UpdateRoleResponse>`)
	role, err = f.GetRole(ctx, root.Account, "ops")
	if err != nil || role.Description != "new" || role.MaxSessionDuration != 43200 {
		t.Fatalf("stored role %+v, want new description and 43200: %v", role, err)
	}

	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {""},
	})
	has(t, res, http.StatusOK, `<UpdateRoleResponse>`)
	role, err = f.GetRole(ctx, root.Account, "ops")
	if err != nil || role.Description != "" || role.MaxSessionDuration != 43200 {
		t.Fatalf("stored role %+v, want empty description and 43200: %v", role, err)
	}

	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"},
	})
	has(t, res, http.StatusOK, `<UpdateRoleResponse>`)
	if role, _ = f.GetRole(ctx, root.Account, "ops"); role.Description != "" || role.MaxSessionDuration != 43200 {
		t.Errorf("a no-op update changed the role: %+v", role)
	}

	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "team", Path: "/team/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"team"}, "MaxSessionDuration": {"3600"},
	})
	has(t, res, http.StatusOK, `<UpdateRoleResponse>`)
	want = "iam:UpdateRole arn:vws:iam::123456789012:role/team/team"
	if len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}

	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"none"}, "Description": {"new"},
	})
	has(t, res, http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "Description": {"new"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "MaxSessionDuration": {""},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "MaxSessionDuration": {"3599"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "MaxSessionDuration": {"43201"},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	long := strings.Repeat("x", iam.MaxRoleDescription+1)
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {long},
	})
	has(t, res, http.StatusBadRequest, `<Code>ValidationError</Code>`)
	if role, _ = f.GetRole(ctx, root.Account, "ops"); role.Description != "" || role.MaxSessionDuration != 43200 {
		t.Errorf("a rejected update changed the role: %+v", role)
	}

	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "svc", Path: iam.ServiceLinkedRolePath + "compute.vws/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"svc"}, "Description": {"new"},
	})
	has(t, res, http.StatusBadRequest, `<Code>UnmodifiableEntity</Code>`)
}

type roleLookupError struct {
	iam.Admin
	err error
}

func (r roleLookupError) GetRole(context.Context, resource.AccountID, string) (iam.Role, error) {
	return iam.Role{}, r.err
}

func TestUpdateRoleFailsClosedWhenTheRoleLookupFails(t *testing.T) {
	lookupErr := &resource.Error{Code: resource.CodeUnavailable, Message: "vws-iam is unavailable"}
	h, f, rec, root := harnessAdmin(t, func(a iam.Admin) iam.Admin {
		return roleLookupError{Admin: a, err: lookupErr}
	})
	ctx := t.Context()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	if _, err := f.CreateRole(ctx, root.Account, iam.RoleInput{
		Name: "ops", Path: "/team/", TrustPolicy: trust, Description: "old",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement":[{"Effect":"Allow","Action":"iam:UpdateRole",` +
		`"Resource":"arn:vws:iam::123456789012:role/ops"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "update", policy); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret, Account: root.Account}
	res := call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {"new"},
	})
	has(t, res, http.StatusServiceUnavailable, `<Code>ServiceUnavailable</Code>`)
	if len(rec.seen) != 0 {
		t.Errorf("authorized on a guessed ARN: %v", rec.seen)
	}
	if role, _ := f.GetRole(ctx, root.Account, "ops"); role.Description != "old" {
		t.Errorf("a failed lookup still updated the role: %+v", role)
	}
}

// harnessAdmin is harnessWith under the name the UpdateRole tests use.
func harnessAdmin(t *testing.T, wrap func(iam.Admin) iam.Admin) (http.Handler, *iam.Fake, *recorder, sigv4.Credential) {
	t.Helper()
	return harnessWith(t, wrap)
}
