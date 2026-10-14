package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// A limited IAM user may call what its policy allows. Anything else is
// UnauthorizedOperation with 403, as EC2 answers.
func TestLimitedUserIsAuthorizedPerAction(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	f := iam.NewFake()
	bob := iam.SigningCredential{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: iam.Principal{Account: account, ARN: "arn:vws:iam::123456789012:user/bob"}}
	f.AddKey(bob)
	f.AddStatement(bob.Principal.ARN, iam.Statement{Effect: iam.Allow, Actions: []string{"ec2:Describe*"}, Resources: []string{"*"}})
	client := iam.WithRoot(iam.NewStatic("AKIDEXAMPLE", "secret", account), f)
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	h := New(Config{Service: svc, Authorizer: client, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now }, Keys: iam.KeyStore(client),
	})})
	bobCred := sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret", Account: account}
	root := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	form := func(action string) string {
		v := url.Values{"Action": {action}, "Version": {Version}}
		if action == "CreateVpc" {
			v.Set("CidrBlock", "10.0.0.0/16")
		}
		return v.Encode()
	}
	if res := signed(t, h, bobCred, now, form("DescribeVpcs")); res.Code != http.StatusOK {
		t.Errorf("allowed DescribeVpcs: %d %s", res.Code, res.Body)
	}
	res := signed(t, h, bobCred, now, form("CreateVpc"))
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "<Code>UnauthorizedOperation</Code>") {
		t.Errorf("denied CreateVpc: %d %s", res.Code, res.Body)
	}
	if res := signed(t, h, root, now, form("CreateVpc")); res.Code != http.StatusOK {
		t.Errorf("root CreateVpc: %d %s", res.Code, res.Body)
	}
}
