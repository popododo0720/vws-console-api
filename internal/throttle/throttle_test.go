package throttle

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func account(t *testing.T, id string) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID](id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)}
}

func takes(l *Limiter, a resource.AccountID, action string, n int) (int, error) {
	for i := range n {
		if _, err := l.Take(a, action); err != nil {
			return i, err
		}
	}
	return n, nil
}

func TestClassOfFollowsTheEC2Categories(t *testing.T) {
	for action, want := range map[string]Class{
		"ec2:RunInstances":                  ClassLaunch,
		"ec2:StartInstances":                ClassLaunch,
		"ec2:DescribeInstances":             ClassDescribe,
		"vws:GetOperation":                  ClassDescribe,
		"ec2:TerminateInstances":            ClassMutate,
		"ec2:CreateVolume":                  ClassMutate,
		"ec2:AuthorizeSecurityGroupIngress": ClassMutate,
	} {
		if got, ok := ClassOf(action); !ok || got != want {
			t.Errorf("ClassOf(%q) = %v, %v; want %v", action, got, ok, want)
		}
	}
	for _, action := range []string{"s3:PutObject", "iam:CreateUser", "sts:AssumeRole", "ec2:", "RunInstances", ""} {
		if _, ok := ClassOf(action); ok {
			t.Errorf("ClassOf(%q) limited; want unlimited", action)
		}
	}
}

// Each class drains at its burst and answers RequestLimitExceeded, the
// ResourceExhausted code every surface maps to its throttle answer.
func TestBurstThenRequestLimitExceeded(t *testing.T) {
	c := newClock()
	l := New(DefaultLimits(), c.now)
	a := account(t, "111111111111")
	for action, burst := range map[string]int{"ec2:RunInstances": 5, "ec2:CreateVolume": 50, "ec2:DescribeVolumes": 100} {
		n, err := takes(l, a, action, burst+1)
		if n != burst {
			t.Errorf("%s: %d passed, want %d", action, n, burst)
		}
		if resource.CodeOf(err) != resource.CodeResourceExhausted ||
			!strings.Contains(err.Error(), "Request limit exceeded.") {
			t.Errorf("%s over the burst: %v", action, err)
		}
	}
}

func TestRefillFollowsTheRate(t *testing.T) {
	c := newClock()
	l := New(DefaultLimits(), c.now)
	a := account(t, "111111111111")
	if n, _ := takes(l, a, "ec2:RunInstances", 6); n != 5 {
		t.Fatalf("burst %d, want 5", n)
	}
	wait, err := l.Take(a, "ec2:RunInstances")
	if err == nil || wait <= 0 || wait > 500*time.Millisecond {
		t.Fatalf("empty bucket: wait %s err %v; want at most 500ms at 2 a second", wait, err)
	}
	c.add(time.Second)
	if n, _ := takes(l, a, "ec2:RunInstances", 3); n != 2 {
		t.Errorf("after 1s at 2 a second: %d passed, want 2", n)
	}
}

// One account that drains its bucket does not slow another account, nor its
// own other actions.
func TestBucketsArePerAccountAndAction(t *testing.T) {
	c := newClock()
	l := New(DefaultLimits(), c.now)
	a, b := account(t, "111111111111"), account(t, "222222222222")
	if _, err := takes(l, a, "ec2:RunInstances", 200); err == nil {
		t.Fatal("200 launches passed a 5-token bucket")
	}
	if n, err := takes(l, b, "ec2:RunInstances", 5); err != nil {
		t.Errorf("account B after A drained: %d passed: %v", n, err)
	}
	if n, err := takes(l, a, "ec2:StartInstances", 5); err != nil {
		t.Errorf("A StartInstances after A drained RunInstances: %d passed: %v", n, err)
	}
	if n, err := takes(l, a, "ec2:DescribeInstances", 100); err != nil {
		t.Errorf("A DescribeInstances after A drained RunInstances: %d passed: %v", n, err)
	}
}

func TestOtherServicesAndANilLimiterPass(t *testing.T) {
	a := account(t, "111111111111")
	l := New(DefaultLimits(), newClock().now)
	if _, err := takes(l, a, "s3:PutObject", 10000); err != nil {
		t.Errorf("s3 throttled here: %v", err)
	}
	if l.size() != 0 {
		t.Errorf("unlimited actions hold %d buckets", l.size())
	}
	var none *Limiter
	if _, err := none.Take(a, "ec2:RunInstances"); err != nil {
		t.Errorf("nil limiter: %v", err)
	}
}

// Requests from many accounts cannot grow the table past MaxKeys.
func TestTableIsBounded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxKeys = 100
	c := newClock()
	l := New(limits, c.now)
	for i := range 1000 {
		if _, err := l.Take(account(t, fmt.Sprintf("%012d", i+1)), "ec2:RunInstances"); err != nil {
			t.Fatal(err)
		}
	}
	if l.size() > 100 {
		t.Errorf("table holds %d buckets, want at most 100", l.size())
	}
}

// A full table prunes to 90% of MaxKeys, so the next MaxKeys/10 new keys
// insert without another scan under the lock.
func TestFullTablePrunesBelowTheCap(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxKeys = 100
	l := New(limits, newClock().now)
	for i := range 100 {
		if _, err := l.Take(account(t, fmt.Sprintf("%012d", i+1)), "ec2:RunInstances"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Take(account(t, "999999999999"), "ec2:RunInstances"); err != nil {
		t.Fatal(err)
	}
	if l.size() != 91 {
		t.Errorf("after one prune the table holds %d buckets, want 91", l.size())
	}
}

func TestValidateBounds(t *testing.T) {
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, mutate := range map[string]func(*Limits){
		"zero burst":       func(l *Limits) { l.Launch.Burst = 0 },
		"huge burst":       func(l *Limits) { l.Describe.Burst = maxBurst + 1 },
		"zero rate":        func(l *Limits) { l.Mutate.PerSecond = 0 },
		"negative rate":    func(l *Limits) { l.Launch.PerSecond = -1 },
		"huge rate":        func(l *Limits) { l.Describe.PerSecond = maxPerSecond + 1 },
		"too few max keys": func(l *Limits) { l.MaxKeys = minMaxKeys - 1 },
		"too many keys":    func(l *Limits) { l.MaxKeys = maxMaxKeys + 1 },
	} {
		l := DefaultLimits()
		mutate(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Concurrent takes never pass more than the burst.
func TestConcurrentTakesHonorTheBurst(t *testing.T) {
	l := New(DefaultLimits(), newClock().now)
	a := account(t, "111111111111")
	var mu sync.Mutex
	passed := 0
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			if _, err := l.Take(a, "ec2:RunInstances"); err == nil {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if passed != 5 {
		t.Errorf("%d of 200 concurrent launches passed, want 5", passed)
	}
}
