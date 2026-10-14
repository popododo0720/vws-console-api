package s3rest

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type recorder struct {
	iam.Client
	seen []string
}

func (r *recorder) Authorize(ctx context.Context, req iam.Request) (iam.Decision, error) {
	r.seen = append(r.seen, req.Action+" "+req.Resource)
	return r.Client.Authorize(ctx, req)
}

// Each S3 route authorizes its own action against an arn:vws:s3 ARN, and a
// deny is AccessDenied with 403.
func TestS3ActionsAndARNs(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	f := iam.NewFake()
	bob := iam.Key{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: iam.Principal{Account: account, ARN: "arn:vws:iam::123456789012:user/bob"}}
	f.AddKey(bob)
	f.AddStatement(bob.Principal.ARN, iam.Statement{Effect: iam.Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}})
	f.AddStatement(bob.Principal.ARN, iam.Statement{Effect: iam.Deny, Actions: []string{"s3:PutObject"}, Resources: []string{"arn:vws:s3:::logs/locked/*"}})
	rec := &recorder{Client: iam.WithRoot(iam.NewStatic("AKIDEXAMPLE", "secret", account), f)}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	h := New(Config{Service: svc, Authorizer: rec, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceS3, Region: resource.RegionName, Now: func() time.Time { return now }, Auth: iam.Authenticator(rec),
	})})
	cred := sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret", Account: account}
	base := "http://127.0.0.1:8082"
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPut, "/logs", ""},
		{http.MethodGet, "/", ""},
		{http.MethodGet, "/logs", ""},
		{http.MethodHead, "/logs", ""},
		{http.MethodPut, "/logs/a.txt", "hi"},
		{http.MethodGet, "/logs/a.txt", ""},
		{http.MethodHead, "/logs/a.txt", ""},
		{http.MethodDelete, "/logs/a.txt", ""},
		{http.MethodDelete, "/logs", ""},
	} {
		if res := call(t, h, cred, now, tc.method, base+tc.path, tc.body, nil); res.Code >= 300 {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, res.Code, res.Body)
		}
	}
	want := []string{
		"s3:CreateBucket arn:vws:s3:::logs",
		"s3:ListAllMyBuckets arn:vws:s3:::*",
		"s3:ListBucket arn:vws:s3:::logs",
		"s3:ListBucket arn:vws:s3:::logs",
		"s3:PutObject arn:vws:s3:::logs/a.txt",
		"s3:GetObject arn:vws:s3:::logs/a.txt",
		"s3:GetObject arn:vws:s3:::logs/a.txt",
		"s3:DeleteObject arn:vws:s3:::logs/a.txt",
		"s3:DeleteBucket arn:vws:s3:::logs",
	}
	if strings.Join(rec.seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("authorized:\n%s\nwant:\n%s", strings.Join(rec.seen, "\n"), strings.Join(want, "\n"))
	}
	call(t, h, cred, now, http.MethodPut, base+"/logs", "", nil)
	res := call(t, h, cred, now, http.MethodPut, base+"/logs/locked/x.txt", "hi", nil)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "<Code>AccessDenied</Code>") {
		t.Errorf("denied put: %d %s", res.Code, res.Body)
	}
	unknown := sigv4.Credential{AccessKey: "AKIDNOPE", Secret: "x", Account: account}
	res = call(t, h, unknown, now, http.MethodGet, base+"/", "", nil)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "<Code>InvalidAccessKeyId</Code>") {
		t.Errorf("unknown key: %d %s", res.Code, res.Body)
	}
}
