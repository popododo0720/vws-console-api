package ec2query

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

// gatedCompute holds every RunInstances inside the backend until opened, so
// a launch is really in flight.
type gatedCompute struct {
	backend.Compute
	entered atomic.Int32
	enter   chan struct{}
	open    chan struct{}
}

func (g *gatedCompute) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	g.entered.Add(1)
	select {
	case g.enter <- struct{}{}:
	default:
	}
	<-g.open
	return g.Compute.RunInstances(ctx, m, req)
}

// #393: with one account's ten instances in flight, a second launch of ten
// and no queue is 503 RequestLimitExceeded in the EC2 error body, never
// reaches the backend and creates nothing. A retry of the same ClientToken
// after the first launch finishes launches once.
func TestLaunchCapRefusesAnInFlightAccount(t *testing.T) {
	now := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	set := fake.New(fake.Options{Now: func() time.Time { return now }}).Set()
	gate := &gatedCompute{Compute: set.Compute, enter: make(chan struct{}, 1), open: make(chan struct{})}
	set.Compute = gate
	limits := throttle.DefaultLaunchLimits()
	limits.PerAccount, limits.Queue = 10, 0
	client := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	h := New(Config{
		Service:    cloud.New(cloud.Config{Backends: set, Launches: throttle.NewLaunches(limits)}),
		Authorizer: client,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
			Now: func() time.Time { return now }, Auth: iam.Authenticator(client),
		}),
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	subnet := newSubnet(t, func(f url.Values) string { return callEC2(t, h, cred, now, f) })
	ten := url.Values{"MinCount": {"10"}, "MaxCount": {"10"}}
	instances := func() int {
		return strings.Count(callEC2(t, h, cred, now, url.Values{"Action": {"DescribeInstances"}}), "<instanceId>")
	}

	first := make(chan *strings.Builder, 1)
	go func() {
		var body strings.Builder
		res := signed(t, h, cred, now, launchForm(subnet, "tok-first", ten).Encode())
		body.WriteString(res.Body.String())
		if res.Code != http.StatusOK {
			body.WriteString("status " + res.Result().Status)
		}
		first <- &body
	}()
	<-gate.enter

	// Without the cap the second launch would block in the backend beside the
	// first, so give it a deadline and fail instead of hanging.
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- signed(t, h, cred, now, launchForm(subnet, "tok-second", ten).Encode()) }()
	var res *httptest.ResponseRecorder
	select {
	case res = <-second:
	case <-time.After(5 * time.Second):
		close(gate.open)
		t.Fatalf("second launch did not return while the first is in flight; backend saw %d launches", gate.entered.Load())
	}
	if res.Code != http.StatusServiceUnavailable ||
		!strings.Contains(res.Body.String(), "<Response><Errors><Error><Code>RequestLimitExceeded</Code>"+
			"<Message>Too many instance launches in flight; retry later.</Message></Error></Errors><RequestID>") {
		t.Fatalf("second launch while the first is in flight: %d %s", res.Code, res.Body)
	}
	if n := gate.entered.Load(); n != 1 {
		t.Errorf("backend saw %d launches, want only the first", n)
	}
	if n := instances(); n != 0 {
		t.Errorf("%d instances while the first launch is held and the second refused, want 0", n)
	}

	close(gate.open)
	if body := <-first; strings.Contains(body.String(), "status ") {
		t.Fatalf("first launch: %s", body)
	}
	if n := instances(); n != 10 {
		t.Fatalf("%d instances after the first launch, want 10", n)
	}
	for range 2 {
		if res := signed(t, h, cred, now, launchForm(subnet, "tok-second", ten).Encode()); res.Code != http.StatusOK {
			t.Fatalf("retry after the first launch finished: %d %s", res.Code, res.Body)
		}
	}
	if n := instances(); n != 20 {
		t.Errorf("%d instances after two retries of one token, want 20", n)
	}
}
