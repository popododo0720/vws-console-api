package console

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Per-address sign-in rate: a bucket of LoginBurst attempts that refills one
// attempt every LoginRefill.
const (
	LoginBurst  = 10
	LoginRefill = 6 * time.Second

	maxBuckets = 10000
)

type bucket struct {
	tokens float64
	at     time.Time
}

// limiter is a token bucket per client address.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newLimiter() *limiter { return &limiter{buckets: map[string]*bucket{}} }

// take spends one attempt for ip. When none is left it returns how long
// until the next one.
func (l *limiter) take(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.prune(now)
		}
		b = &bucket{tokens: LoginBurst, at: now}
		l.buckets[ip] = b
	}
	b.tokens = min(LoginBurst, b.tokens+float64(now.Sub(b.at))/float64(LoginRefill))
	b.at = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) * float64(LoginRefill))
	}
	b.tokens--
	return true, 0
}

// prune drops full buckets (idle long enough to have refilled), then
// arbitrary ones, so spraying addresses cannot grow the table without bound.
func (l *limiter) prune(now time.Time) {
	full := time.Duration(LoginBurst) * LoginRefill
	for ip, b := range l.buckets {
		if now.Sub(b.at) >= full {
			delete(l.buckets, ip)
		}
	}
	for ip := range l.buckets {
		if len(l.buckets) < maxBuckets {
			break
		}
		delete(l.buckets, ip)
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int((d+time.Second-1)/time.Second))))
}

// browserWriteOK enforces, on sign-in and on every state-changing cookie
// request, a JSON Content-Type (no HTML form can send one) and an Origin that
// is the console's own host or one in Config.Origins.
func (h *handler) browserWriteOK(w http.ResponseWriter, r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		unsupportedMedia(w)
		return false
	}
	if !h.originOK(r.Header.Get("Origin"), r.Host) {
		writeErr(w, r, resource.Denied("origin not allowed"))
		return false
	}
	return true
}

func (h *handler) originOK(origin, host string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	for _, o := range h.origins {
		if origin == o {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return false
	}
	return u.Host == host
}

// unsupportedMedia answers 415 in the console's error shape.
func unsupportedMedia(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": map[string]string{
		"code": "UnsupportedMediaType", "field": "Content-Type", "message": "application/json required",
	}})
}
