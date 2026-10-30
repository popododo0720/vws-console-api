package console

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
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

// ParseTrustedProxies parses -trusted-proxies: a comma-separated list of
// CIDRs (a bare address means a single host). Empty yields nil.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, raw := range strings.Split(list, ",") {
		raw = strings.TrimSpace(raw)
		var p netip.Prefix
		var err error
		if strings.Contains(raw, "/") {
			p, err = netip.ParsePrefix(raw)
			if err == nil && p != p.Masked() {
				err = fmt.Errorf("host bits set, did you mean %s", p.Masked())
			}
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(raw)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// clientIP is the address sign-in limits, lockout and logs key on. It is
// the TCP peer unless that peer is a trusted proxy; then X-Forwarded-For
// (every header line, in order) is walked right to left and the first
// untrusted entry is the client. Entries left of it are client-controlled
// and never read. If every entry is trusted the leftmost is used (an
// internal client); if the header is missing or any entry walked is not an
// IP the peer address is used.
func (h *handler) clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !h.isTrusted(addr) {
		return peer
	}
	var hops []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(line, ",")...)
	}
	var last netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			return peer
		}
		if !h.isTrusted(a) {
			return a.String()
		}
		last = a
	}
	if last.IsValid() {
		return last.String()
	}
	return peer
}

func (h *handler) isTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range h.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int((d+time.Second-1)/time.Second))))
}

// browserWriteOK enforces, on sign-in and on every state-changing cookie
// request, an Origin that is the console's own host or one in Config.Origins
// and, when needJSON, a JSON Content-Type (no HTML form can send one). An
// object upload skips the JSON rule to keep the object's Content-Type; the
// Origin check and the X-CSRF-Token header that authenticate requires still
// refuse a cross-site request (#224).
func (h *handler) browserWriteOK(w http.ResponseWriter, r *http.Request, needJSON bool) bool {
	if needJSON {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			unsupportedMedia(w)
			return false
		}
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
