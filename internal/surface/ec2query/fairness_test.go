package ec2query

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// quietAccountBound is how long the quiet account's launches may take while
// another account floods RunInstances. The gate makes them wait for none of
// the flood, so the bound only covers the handler and the fake backend.
const quietAccountBound = 2 * time.Second

// floodCompute holds one account's launches in the backend until open is
// closed and records the most of its instances in the backend at once.
type floodCompute struct {
	backend.Compute
	hold  resource.AccountID
	open  chan struct{}
	calls atomic.Int32

	mu         sync.Mutex
	held, peak int
}

func (f *floodCompute) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	if m.Account != f.hold {
		return f.Compute.RunInstances(ctx, m, req)
	}
	f.calls.Add(1)
	f.mu.Lock()
	f.held += req.Count
	f.peak = max(f.peak, f.held)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.held -= req.Count
		f.mu.Unlock()
	}()
	<-f.open
	return f.Compute.RunInstances(ctx, m, req)
}

func (f *floodCompute) inBackend() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// countingAuthorizer counts the RunInstances calls it authorizes per account,
// so the test knows when the flood has passed the request limit.
type countingAuthorizer struct {
	iam.Authorizer
	mu       sync.Mutex
	launches map[resource.AccountID]int
}

func (c *countingAuthorizer) Authorize(ctx context.Context, req iam.Request) (iam.Decision, error) {
	if req.Action == "ec2:RunInstances" {
		c.mu.Lock()
		c.launches[req.Principal.Account]++
		c.mu.Unlock()
	}
	return c.Authorizer.Authorize(ctx, req)
}

func (c *countingAuthorizer) authorized(a resource.AccountID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.launches[a]
}

// #393: account A sends 200 one-instance launches at once and B sends 5.
// Every launch of A the gate admits stays in the backend for the whole run,
// so A is at its in-flight cap with the rest of its flood queued or
// refused. B's five launches are answered 200 within quietAccountBound,
// before any of A's queued launches, and A never has more than its cap in
// the backend. Under the default request limit A's flood stops at its
// RunInstances bucket; with that limit raised the whole flood reaches the
// launch gate. Afterwards every launch of A is answered 200 or 503
// RequestLimitExceeded, and each 200 is one backend call and one instance.
func TestQuietAccountLaunchesWithinTheBoundDuringAFlood(t *testing.T) {
	raised := throttle.DefaultLimits()
	raised.Launch.Burst = 1000
	for _, tc := range []struct {
		name     string
		requests throttle.Limits
		// held is how many of A's launches the gate admits.
		held int
	}{
		{name: "default request limit", requests: throttle.DefaultLimits(), held: throttle.DefaultLimits().Launch.Burst},
		{name: "request limit raised", requests: raised, held: throttle.DefaultLaunchLimits().PerAccount},
	} {
		t.Run(tc.name, func(t *testing.T) { floodAndQuiet(t, tc.requests, tc.held) })
	}
}

func floodAndQuiet(t *testing.T, requests throttle.Limits, held int) {
	const flood, quiet = 200, 5
	now := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
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
	authz := &countingAuthorizer{Authorizer: client, launches: map[resource.AccountID]int{}}
	set := fake.New(fake.Options{Now: func() time.Time { return now }}).Set()
	compute := &floodCompute{Compute: set.Compute, hold: accountA, open: make(chan struct{})}
	set.Compute = compute
	launches := throttle.DefaultLaunchLimits()
	h := New(Config{
		Service:    cloud.New(cloud.Config{Backends: set, Launches: throttle.NewLaunches(launches)}),
		Authorizer: authz,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
			Now: func() time.Time { return now }, Auth: iam.Authenticator(client),
		}),
		Requests: throttle.New(requests, func() time.Time { return now }),
	})
	a := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: accountA}
	b := sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret", Account: accountB}
	subnetA := newSubnet(t, func(f url.Values) string { return callEC2(t, h, a, now, f) })
	subnetB := newSubnet(t, func(f url.Values) string { return callEC2(t, h, b, now, f) })
	// instances counts the account's instances across pages.
	instances := func(c sigv4.Credential) int {
		n, next := 0, ""
		for {
			page := url.Values{"Action": {"DescribeInstances"}, "MaxResults": {"100"}}
			if next != "" {
				page.Set("NextToken", next)
			}
			body := callEC2(t, h, c, now, page)
			n += strings.Count(body, "<instanceId>")
			if !strings.Contains(body, "<nextToken>") {
				return n
			}
			next = xmlText(t, body, "nextToken")
		}
	}
	released := false
	release := func() {
		if !released {
			released = true
			close(compute.open)
		}
	}
	defer release()

	floodDone := make(chan *httptest.ResponseRecorder, flood)
	var answered atomic.Int32
	for i := range flood {
		req := signedLaunch(t, a, now, launchForm(subnetA, fmt.Sprintf("tok-a-%d", i), nil))
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			answered.Add(1)
			floodDone <- rec
		}()
	}
	// The flood is settled when every launch is refused by the request limit
	// or authorized, and the admitted ones are in the backend. A's queued
	// launches give up after the 10 s queue wait, so everything up to the
	// release below must take less than that; it takes well under a second.
	waitUntil(t, "the flood reaches the gate", func() bool {
		return int(answered.Load())+authz.authorized(accountA) == flood && compute.inBackend() == held
	})
	answeredBeforeB := int(answered.Load())

	quietDone := make(chan *httptest.ResponseRecorder, quiet)
	start := time.Now()
	for i := range quiet {
		req := signedLaunch(t, b, now, launchForm(subnetB, fmt.Sprintf("tok-b-%d", i), nil))
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			quietDone <- rec
		}()
	}
	for i := range quiet {
		select {
		case rec := <-quietDone:
			if rec.Code != http.StatusOK {
				t.Fatalf("B's launch %d during A's flood: %d %s", i, rec.Code, rec.Body)
			}
		case <-time.After(quietAccountBound - time.Since(start)):
			t.Fatalf("B had %d of %d launches answered after %v during A's flood, bound %v",
				i, quiet, time.Since(start), quietAccountBound)
		}
	}
	if n := instances(b); n != quiet {
		t.Errorf("B holds %d instances after its launches, want %d", n, quiet)
	}
	if n := int(answered.Load()); n != answeredBeforeB {
		t.Errorf("%d of A's launches answered while B launched, want none past the %d refused",
			n-answeredBeforeB, answeredBeforeB)
	}
	if n := compute.inBackend(); n != held {
		t.Errorf("A has %d instances in the backend after B launched, want %d still held", n, held)
	}

	release()
	ok := 0
	for range flood {
		rec := <-floodDone
		switch {
		case rec.Code == http.StatusOK:
			ok++
		case rec.Code == http.StatusServiceUnavailable &&
			strings.Contains(rec.Body.String(), "<Code>RequestLimitExceeded</Code>"):
		default:
			t.Errorf("A's launch: %d %s", rec.Code, rec.Body)
		}
	}
	if compute.peak > launches.PerAccount {
		t.Errorf("A had %d instances in the backend at once, cap %d", compute.peak, launches.PerAccount)
	}
	if ok < held {
		t.Errorf("%d of A's launches succeeded, want at least the %d admitted", ok, held)
	}
	if calls := int(compute.calls.Load()); calls != ok {
		t.Errorf("backend saw %d of A's launches for %d answered 200, want one each", calls, ok)
	}
	if n := instances(a); n != ok {
		t.Errorf("A holds %d instances for %d launches answered 200, want one each", n, ok)
	}
}

// signedLaunch signs a RunInstances request on the test goroutine, so the
// flood's goroutines only serve it.
func signedLaunch(t *testing.T, cred sigv4.Credential, now time.Time, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/",
		strings.NewReader(form.Encode()))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	return req
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for: %s", what)
}
