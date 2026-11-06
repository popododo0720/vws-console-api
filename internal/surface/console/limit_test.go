package console

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/service"
)

var t0 = time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)

func TestLimiterThrottlesAfterBurstAndRefills(t *testing.T) {
	l := newLimiter(3, time.Second, 100)
	for i := range 3 {
		if ok, _ := l.take("k", t0); !ok {
			t.Fatalf("take %d refused inside the burst", i)
		}
	}
	ok, wait := l.take("k", t0)
	if ok || wait != time.Second {
		t.Fatalf("over the burst: ok=%v wait=%s, want refused for 1s", ok, wait)
	}
	if ok, _ := l.take("k", t0.Add(time.Second)); !ok {
		t.Fatal("refused after one refill")
	}
	if ok, _ := l.take("k", t0.Add(time.Second)); ok {
		t.Fatal("one refill gave more than one attempt")
	}
	// A full window refills the whole burst and no more.
	later := t0.Add(time.Hour)
	for i := range 3 {
		if ok, _ := l.take("k", later); !ok {
			t.Fatalf("take %d refused after the window", i)
		}
	}
	if ok, _ := l.take("k", later); ok {
		t.Fatal("bucket grew past its burst")
	}
}

func TestLimiterKeysAreIsolated(t *testing.T) {
	l := newLimiter(1, time.Minute, 100)
	if ok, _ := l.take("a", t0); !ok {
		t.Fatal("first take of a refused")
	}
	if ok, _ := l.take("a", t0); ok {
		t.Fatal("second take of a allowed")
	}
	if ok, _ := l.take("b", t0); !ok {
		t.Fatal("b refused because a ran dry")
	}
}

func TestLimiterRefundIsCappedAtTheBurst(t *testing.T) {
	l := newLimiter(2, time.Minute, 100)
	l.take("k", t0)
	l.refund("k")
	l.refund("k")
	l.refund("never-taken")
	for i := range 2 {
		if ok, _ := l.take("k", t0); !ok {
			t.Fatalf("take %d refused", i)
		}
	}
	if ok, _ := l.take("k", t0); ok {
		t.Fatal("refunds grew the bucket past its burst")
	}
	if n := l.size(); n != 1 {
		t.Fatalf("refund of an unknown key added it: %d keys", n)
	}
}

// Spraying keys (addresses or user names) never holds more than maxKeys.
func TestLimiterMemoryIsBounded(t *testing.T) {
	l := newLimiter(5, time.Minute, 100)
	for i := range 10000 {
		l.take("k"+strconv.Itoa(i), t0)
	}
	if n := l.size(); n > 100 {
		t.Fatalf("%d keys held, want at most 100", n)
	}
}

// Concurrent takes on one key never hand out more than the burst.
func TestLimiterIsConcurrencySafe(t *testing.T) {
	l := newLimiter(100, time.Hour, 100)
	var granted atomic.Int64
	var wg sync.WaitGroup
	for g := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if ok, _ := l.take("k", t0); ok {
					granted.Add(1)
				}
				l.take("other"+strconv.Itoa(g), t0)
			}
		}()
	}
	wg.Wait()
	if n := granted.Load(); n != 100 {
		t.Fatalf("%d attempts granted, want exactly the burst of 100", n)
	}
}

func TestLoginLimitsValidate(t *testing.T) {
	if err := DefaultLoginLimits().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, mut := range map[string]func(*LoginLimits){
		"zero ip burst":       func(l *LoginLimits) { l.IPBurst = 0 },
		"negative user burst": func(l *LoginLimits) { l.UserBurst = -1 },
		"huge ip burst":       func(l *LoginLimits) { l.IPBurst = 10001 },
		"tiny ip refill":      func(l *LoginLimits) { l.IPRefill = time.Millisecond },
		"huge user refill":    func(l *LoginLimits) { l.UserRefill = 25 * time.Hour },
		"few keys":            func(l *LoginLimits) { l.MaxKeys = 99 },
		"many keys":           func(l *LoginLimits) { l.MaxKeys = 1000001 },
	} {
		l := DefaultLoginLimits()
		mut(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, l)
		}
	}
	got := (LoginLimits{UserBurst: 3}).withDefaults()
	if got.UserBurst != 3 || got.IPBurst != LoginBurst || got.MaxKeys != LoginMaxKeys {
		t.Errorf("withDefaults: %+v", got)
	}
}

// limitedEnv is a loginEnv whose handler has the given limits and logger.
func limitedEnv(t *testing.T, lim LoginLimits, log *slog.Logger) loginEnv {
	t.Helper()
	e := newLoginEnv(t)
	e.h = New(Config{
		IAM: iam.WithRoot(e.root, e.fake), Logger: log, LoginLimits: lim,
		Now: func() time.Time { return *e.clock },
	})
	return e
}

func (e loginEnv) loginFrom(t *testing.T, ip, user, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"account":"123456789012","userName":"` + user + `","password":"` + password + `"}`
	if password != "correct horse 1" {
		// A guess carries an MFA code too, to prove it is never logged.
		body = strings.Replace(body, `}`, `,"mfaCode":"654321"}`, 1)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://127.0.0.1:8080/api/v1/auth/login", strings.NewReader(body))
	req.RemoteAddr = ip + ":5555"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// A password guess spread over many addresses is throttled per account and
// user name, case-insensitively, without touching other users; the bucket
// refills over time. The throttle is logged and counted with no secret.
func TestLoginIsRateLimitedPerUserAcrossAddresses(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	reader := sdkmetric.NewManualReader()
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name), obs.WithOverride(func(c *obs.Config) {
		c.MetricReaders = []sdkmetric.Reader{reader}
		c.LogOutput = io.Discard
	}))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
	})
	var logs bytes.Buffer
	e := limitedEnv(t, LoginLimits{UserBurst: 3, UserRefill: time.Minute}, slog.New(slog.NewJSONHandler(&logs, nil)))

	for i := range 3 {
		rec := e.loginFrom(t, "198.51.100."+strconv.Itoa(i+1), "bob", "wrong pass 1")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	for _, user := range []string{"bob", "BOB"} {
		rec := e.loginFrom(t, "198.51.100.50", user, "correct horse 1")
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
			t.Fatalf("%s from a fresh address: %d %v %s", user, rec.Code, rec.Header(), rec.Body)
		}
		if !strings.Contains(rec.Body.String(), `"ResourceExhausted"`) {
			t.Errorf("throttle body %s", rec.Body)
		}
	}
	if rec := e.loginFrom(t, "198.51.100.50", "alice", "wrong pass 1"); rec.Code != http.StatusUnauthorized {
		t.Errorf("another user was throttled: %d %s", rec.Code, rec.Body)
	}
	*e.clock = e.clock.Add(time.Minute)
	if rec := e.loginFrom(t, "198.51.100.51", "bob", "correct horse 1"); rec.Code != http.StatusOK {
		t.Errorf("after refill: %d %s", rec.Code, rec.Body)
	}

	out := logs.String()
	if !strings.Contains(out, "console sign-in rate limited") || !strings.Contains(out, `"limit":"throttled_user"`) {
		t.Errorf("no throttle log: %s", out)
	}
	for _, secret := range []string{"wrong pass 1", "correct horse 1", "654321", "123456789012"} {
		if strings.Contains(out, secret) {
			t.Errorf("log carries %q: %s", secret, out)
		}
	}
	if n := auditCount(t, reader, throttledByUser); n != 2 {
		t.Errorf("throttled_user audit count %d, want 2", n)
	}
}

// A failed or throttled sign-in logs no submitted user name, since people
// type a password into that box; a success names the real user.
func TestFailedLoginLogsNoUserName(t *testing.T) {
	var logs bytes.Buffer
	e := limitedEnv(t, LoginLimits{UserBurst: 1, UserRefill: time.Hour}, slog.New(slog.NewJSONHandler(&logs, nil)))
	const typed = "Tr0ub4dor-in-name-box"

	if rec := e.loginFrom(t, "198.51.100.1", typed, "wrong pass 1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failed sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := e.loginFrom(t, "198.51.100.2", typed, "wrong pass 1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled sign-in: %d %s", rec.Code, rec.Body)
	}
	out := logs.String()
	for _, want := range []string{"console sign-in failed", "console sign-in rate limited", `"limit":"throttled_user"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %s", want, out)
		}
	}
	if strings.Contains(out, typed) || strings.Contains(out, `"user"`) {
		t.Errorf("failed sign-in logged a user name: %s", out)
	}

	logs.Reset()
	if rec := e.loginFrom(t, "198.51.100.3", "bob", "correct horse 1"); rec.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", rec.Code, rec.Body)
	}
	if out := logs.String(); !strings.Contains(out, `"msg":"console sign-in"`) || !strings.Contains(out, `"user":"bob"`) {
		t.Errorf("success log does not name the user: %s", out)
	}
}

func auditCount(t *testing.T, reader *sdkmetric.ManualReader, outcome string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != obs.MetricAuditEvents {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T", m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				action, _ := dp.Attributes.Value("action")
				got, _ := dp.Attributes.Value("outcome")
				if action.AsString() == auditActionLogin && got.AsString() == outcome {
					n += dp.Value
				}
			}
		}
	}
	return n
}

// A success gives the user attempt back but not the address attempt, so a
// caller who knows one password cannot keep an address open for guessing
// other users.
func TestLoginSuccessRefundsTheUserButNotTheAddress(t *testing.T) {
	e := limitedEnv(t, LoginLimits{IPBurst: 3, UserBurst: 1}, nil)
	for i := range 3 {
		if rec := e.loginFrom(t, "203.0.113.7", "bob", "correct horse 1"); rec.Code != http.StatusOK {
			t.Fatalf("sign-in %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := e.loginFrom(t, "203.0.113.7", "bob", "correct horse 1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("address past its burst after successes: %d %s", rec.Code, rec.Body)
	}
	// Three successes with a user burst of one: each gave its attempt back.
	if rec := e.loginFrom(t, "203.0.113.8", "bob", "correct horse 1"); rec.Code != http.StatusOK {
		t.Fatalf("user bucket drained by successes: %d %s", rec.Code, rec.Body)
	}
}

// A sign-in refused because every hashing slot is busy checked no password,
// so it does not spend the user's attempt.
func TestBusySignInKeepsTheUserAttempt(t *testing.T) {
	e := limitedEnv(t, LoginLimits{UserBurst: 1}, nil)
	release := e.fake.OccupyHashing()
	if rec := e.loginFrom(t, "203.0.113.9", "bob", "correct horse 1"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy: %d %s", rec.Code, rec.Body)
	}
	release()
	if rec := e.loginFrom(t, "203.0.113.10", "bob", "correct horse 1"); rec.Code != http.StatusOK {
		t.Fatalf("after busy: %d %s", rec.Code, rec.Body)
	}
}

// Parallel guesses for one user from many addresses get at most the burst
// checked by IAM: each 401 spent an attempt that was never given back. A
// busy answer gives its attempt back, so it is not counted.
func TestConcurrentGuessesForOneUserStopAtTheBurst(t *testing.T) {
	e := limitedEnv(t, LoginLimits{UserBurst: 4, UserRefill: time.Hour}, nil)
	var checked atomic.Int64
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := e.loginFrom(t, "198.18.0."+strconv.Itoa(i+1), "bob", "wrong pass 1")
			switch rec.Code {
			case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			case http.StatusUnauthorized:
				checked.Add(1)
			default:
				t.Errorf("guess %d: %d %s", i, rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
	if n := checked.Load(); n > 4 || n < 1 {
		t.Fatalf("%d guesses checked by IAM, want 1 to 4", n)
	}
}
