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
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

// #393: a launch past the account's RunInstances bucket is 503
// RequestLimitExceeded in the EC2 error body, creates nothing, and leaves
// another account's bucket alone. A retry with the same ClientToken after
// the refill launches once.
func TestRequestLimitExceededIsAWSShaped(t *testing.T) {
	now := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	clock := now
	accountA, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	accountB, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	f := iam.NewFake()
	bob := iam.Key{
		AccessKey: "AKIDBOB", Secret: "bobsecret",
		Principal: iam.Principal{Account: accountB, ARN: "arn:vws:iam::210987654321:user/bob"},
	}
	f.AddKey(bob)
	f.AddStatement(bob.Principal.ARN, iam.Statement{
		Effect: iam.Allow, Actions: []string{"ec2:*"}, Resources: []string{"*"},
	})
	client := iam.WithRoot(iam.NewStatic("AKIDEXAMPLE", "secret", accountA), f)
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	h := New(Config{
		Service: svc, Authorizer: client,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Region: resource.RegionName,
			Now: func() time.Time { return now }, Auth: iam.Authenticator(client),
		}),
		Requests: throttle.New(throttle.DefaultLimits(), func() time.Time { return clock }),
	})
	a := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: accountA}
	b := sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret", Account: accountB}
	subnetA := newSubnet(t, func(f url.Values) string { return callEC2(t, h, a, now, f) })
	subnetB := newSubnet(t, func(f url.Values) string { return callEC2(t, h, b, now, f) })

	for i := range 5 {
		res := signed(t, h, a, now, launchForm(subnetA, "tok-"+string(rune('a'+i)), nil).Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("launch %d in the burst: %d %s", i, res.Code, res.Body)
		}
	}
	res := signed(t, h, a, now, launchForm(subnetA, "tok-over", nil).Encode())
	body := res.Body.String()
	if res.Code != http.StatusServiceUnavailable ||
		!strings.Contains(body, "<Response><Errors><Error><Code>RequestLimitExceeded</Code>"+
			"<Message>Request limit exceeded.</Message></Error></Errors><RequestID>") {
		t.Fatalf("sixth launch: %d %s", res.Code, body)
	}
	if n := strings.Count(callEC2(t, h, a, now, url.Values{"Action": {"DescribeInstances"}}), "<instanceId>"); n != 5 {
		t.Errorf("account A holds %d instances after a throttled launch, want 5", n)
	}
	if res := signed(t, h, b, now, launchForm(subnetB, "tok-b", nil).Encode()); res.Code != http.StatusOK {
		t.Errorf("account B while A is throttled: %d %s", res.Code, res.Body)
	}

	clock = clock.Add(time.Second)
	for range 2 {
		if res := signed(t, h, a, now, launchForm(subnetA, "tok-over", nil).Encode()); res.Code != http.StatusOK {
			t.Fatalf("retry after the refill: %d %s", res.Code, res.Body)
		}
	}
	if n := strings.Count(callEC2(t, h, a, now, url.Values{"Action": {"DescribeInstances"}}), "<instanceId>"); n != 6 {
		t.Errorf("account A holds %d instances after two retries of one token, want 6", n)
	}
}
