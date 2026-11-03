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

// Default sign-in limits. Per address: a bucket of LoginBurst attempts that
// refills one attempt every LoginRefill. Per (account, user name): a bucket
// of LoginUserBurst attempts that refills one every LoginUserRefill; a
// successful sign-in gives its attempt back, so the user bucket only drains
// on failures and spreads a password guess over many addresses no faster
// than this rate. vws-iam keeps its own lockout counters; these buckets are
// a defense in depth in front of it and hold no lockout state of their own.
const (
	LoginBurst      = 10
	LoginRefill     = 6 * time.Second
	LoginUserBurst  = 10
	LoginUserRefill = 30 * time.Second
	LoginMaxKeys    = 10000
)

// Bounds a LoginLimits field must stay within.
const (
	minLoginRefill  = 100 * time.Millisecond
	maxLoginRefill  = 24 * time.Hour
	maxLoginBurst   = 10000
	minLoginMaxKeys = 100
	maxLoginMaxKeys = 1000000
)

// LoginLimits sets the gateway sign-in rate limits. A zero field takes its
// default (DefaultLoginLimits).
type LoginLimits struct {
	// IPBurst and IPRefill bound attempts per client address.
	IPBurst  int
	IPRefill time.Duration
	// UserBurst and UserRefill bound failed attempts per account and user
	// name, from every address together.
	UserBurst  int
	UserRefill time.Duration
	// MaxKeys bounds each table (addresses, users), so spraying keys cannot
	// grow memory without bound.
	MaxKeys int
}

// DefaultLoginLimits returns the default sign-in limits.
func DefaultLoginLimits() LoginLimits {
	return LoginLimits{
		IPBurst: LoginBurst, IPRefill: LoginRefill,
		UserBurst: LoginUserBurst, UserRefill: LoginUserRefill,
		MaxKeys: LoginMaxKeys,
	}
}

func (l LoginLimits) withDefaults() LoginLimits {
	d := DefaultLoginLimits()
	if l.IPBurst == 0 {
		l.IPBurst = d.IPBurst
	}
	if l.IPRefill == 0 {
		l.IPRefill = d.IPRefill
	}
	if l.UserBurst == 0 {
		l.UserBurst = d.UserBurst
	}
	if l.UserRefill == 0 {
		l.UserRefill = d.UserRefill
	}
	if l.MaxKeys == 0 {
		l.MaxKeys = d.MaxKeys
	}
	return l
}

// Validate reports the first field outside its bounds: bursts 1 to 10000,
// refills 100ms to 24h, MaxKeys 100 to 1000000.
func (l LoginLimits) Validate() error {
	for _, b := range []struct {
		name string
		v    int
	}{{"ip burst", l.IPBurst}, {"user burst", l.UserBurst}} {
		if b.v < 1 || b.v > maxLoginBurst {
			return fmt.Errorf("sign-in %s %d: want 1 to %d", b.name, b.v, maxLoginBurst)
		}
	}
	for _, r := range []struct {
		name string
		v    time.Duration
	}{{"ip refill", l.IPRefill}, {"user refill", l.UserRefill}} {
		if r.v < minLoginRefill || r.v > maxLoginRefill {
			return fmt.Errorf("sign-in %s %s: want %s to %s", r.name, r.v, minLoginRefill, maxLoginRefill)
		}
	}
	if l.MaxKeys < minLoginMaxKeys || l.MaxKeys > maxLoginMaxKeys {
		return fmt.Errorf("sign-in max keys %d: want %d to %d", l.MaxKeys, minLoginMaxKeys, maxLoginMaxKeys)
	}
	return nil
}

type bucket struct {
	tokens float64
	at     time.Time
}

// limiter is a token bucket per key (a client address, or an account and
// user name).
type limiter struct {
	burst   float64
	refill  time.Duration
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

func newLimiter(burst int, refill time.Duration, maxKeys int) *limiter {
	return &limiter{burst: float64(burst), refill: refill, maxKeys: maxKeys, buckets: map[string]*bucket{}}
}

// take spends one attempt for key. When none is left it returns how long
// until the next one.
func (l *limiter) take(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			l.prune(now)
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+float64(now.Sub(b.at))/float64(l.refill))
	b.at = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) * float64(l.refill))
	}
	b.tokens--
	return true, 0
}

// refund gives back one attempt taken for key, up to the burst. A key
// pruned since the take is already full, so it is not recreated.
func (l *limiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[key]; b != nil {
		b.tokens = min(l.burst, b.tokens+1)
	}
}

// size is the number of keys held (tests).
func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// prune drops full buckets (idle long enough to have refilled), then
// arbitrary ones, so spraying keys cannot grow the table without bound.
func (l *limiter) prune(now time.Time) {
	full := time.Duration(l.burst) * l.refill
	for k, b := range l.buckets {
		if now.Sub(b.at) >= full {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < l.maxKeys {
			break
		}
		delete(l.buckets, k)
	}
}

// userKey keys the per-user bucket. IAM user names are unique without
// regard to case, so case variants share one bucket.
func userKey(a resource.AccountID, user string) string {
	return a.String() + "/" + strings.ToLower(user)
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
