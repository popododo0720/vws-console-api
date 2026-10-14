package console

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.0/8, fd00::/8 ,192.0.2.1")
	if err != nil || len(got) != 3 || got[2].String() != "192.0.2.1/32" {
		t.Fatalf("got %v %v", got, err)
	}
	if got, err := ParseTrustedProxies(""); err != nil || got != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "not-a-cidr", "10.0.0.0/8,,", "10.1.2.3/8"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientIPResolution(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8,fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		trusted bool
		remote  string
		xff     []string
		want    string
	}{
		{"no flag ignores xff", false, "10.0.0.5:1", []string{"203.0.113.7"}, "10.0.0.5"},
		{"trusted proxy", true, "10.0.0.5:1", []string{"203.0.113.7"}, "203.0.113.7"},
		{"untrusted peer ignores xff", true, "198.51.100.9:1", []string{"203.0.113.7"}, "198.51.100.9"},
		{"forged leftmost entry is not used", true, "10.0.0.5:1", []string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"multiple hops", true, "10.0.0.5:1", []string{"1.2.3.4, 203.0.113.7, 10.9.9.9", "10.1.1.1"}, "203.0.113.7"},
		{"ipv6", true, "[fd00::1]:443", []string{"2001:db8::7, fd00::2"}, "2001:db8::7"},
		{"ipv6 bracketed entry", true, "[fd00::1]:443", []string{"[2001:db8::8]:5"}, "2001:db8::8"},
		{"all trusted uses leftmost", true, "10.0.0.5:1", []string{"10.3.3.3, 10.2.2.2"}, "10.3.3.3"},
		{"missing header", true, "10.0.0.5:1", nil, "10.0.0.5"},
		{"malformed header", true, "10.0.0.5:1", []string{"203.0.113.7, garbage"}, "10.0.0.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &handler{}
			if c.trusted {
				h.trusted = trusted
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := h.clientIP(r); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

// Behind a trusted proxy every user shares the proxy's address; the limiter
// must key on the forwarded client so one user cannot exhaust it for all.
func TestRateLimitBehindTrustedProxyIsPerClient(t *testing.T) {
	e := newLoginEnv(t)
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	e.h = newLoginHandler(t, e, trusted)
	send := func(xff string) int {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login",
			strings.NewReader(`{"account":"123456789012","userName":"bob","password":"wrong pass 1"}`))
		r.RemoteAddr = "10.0.0.5:1"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		return rec.Code
	}
	for range LoginBurst + 1 {
		send("203.0.113.1")
	}
	if code := send("203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("attacker not limited: %d", code)
	}
	// A spoofed leftmost entry does not get the attacker a fresh bucket.
	if code := send("198.51.100.1, 203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("spoofed xff escaped the limit: %d", code)
	}
	if code := send("203.0.113.2"); code == http.StatusTooManyRequests {
		t.Fatalf("other client behind the proxy limited: %d", code)
	}
}

func newLoginHandler(t *testing.T, e loginEnv, trusted []netip.Prefix) http.Handler {
	t.Helper()
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	return New(Config{Service: svc, IAM: iam.WithRoot(e.root, e.fake), TrustedProxies: trusted, Now: func() time.Time { return *e.clock }})
}
