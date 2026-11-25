package pveclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"time"
)

// Failover limits.
const (
	// QuorumFresh is how old a positive quorum result may be when a write
	// is sent to its address.
	QuorumFresh = 5 * time.Second
	// AttemptHeaderTimeout bounds the wait for response headers of one GET
	// attempt while another address is left to try.
	AttemptHeaderTimeout = time.Second
	// FailoverBudget stops one request from starting a new attempt on
	// another address after this long.
	FailoverBudget = 4 * time.Second
)

type pinnedKey struct{}

// WithEndpoint returns a context that sends the request to address i only:
// no failover and no index change. The quorum gate probes this way.
func WithEndpoint(ctx context.Context, i int) context.Context {
	return context.WithValue(ctx, pinnedKey{}, i)
}

// Endpoints is the http.RoundTripper of a client that talks to one cluster
// through several node addresses. It keeps one ordered list and one current
// index. Every request goes to the current address; when that address fails
// the index moves to the next one, wrapping around.
//
// A request moves on only when the failure proves the next address cannot
// double-apply it. A GET may move after any transport error, since reading
// twice changes nothing. Any other method, HEAD included, moves only when no
// connection to the address was ever obtained: a dial or TLS handshake
// failure, before the first byte of the request was written. Once a connection exists, a failed
// write returns its error and the caller reconciles through PVE (task UPID
// and launch marker) instead of sending the request to a second node.
//
// Each attempt is bounded: the base transport caps connect and TLS, and a GET
// with another address left to try waits AttemptHeaderTimeout for headers.
// FailoverBudget stops a walk from starting new attempts.
//
// A write is sent to an address only while that address itself has a
// positive quorum result (MarkQuorate) no older than QuorumFresh. Otherwise
// it is not sent and the refusal is returned; this holds for the first
// attempt and for every pre-connect retry.
//
// Requests go only to the registered addresses, never follow a redirect to
// another host and never carry the Authorization header anywhere else. TLS
// verifies each address against the CA of the base transport under that
// address's own host name.
type Endpoints struct {
	base    *http.Transport
	hosts   []string // scheme-less origins, in registration order
	cur     atomic.Int64
	quorate []atomic.Int64 // unix nanoseconds of the last positive quorum result per address; 0 is none
	refusal error
	now     func() time.Time
}

// NewEndpoints returns the failover transport over base for urls, which must
// be HTTPS origins without a path. refusal is the error a write that no
// address with fresh quorum can take returns.
func NewEndpoints(base *http.Transport, urls []string, refusal error) (*Endpoints, error) {
	if base == nil || len(urls) == 0 || refusal == nil {
		return nil, errors.New("pveclient: endpoints need a transport, an address and a refusal")
	}
	hosts := make([]string, len(urls))
	for i, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("pveclient: endpoint %d is not an https origin", i+1)
		}
		hosts[i] = u.Host
	}
	return &Endpoints{
		base: base, hosts: hosts, quorate: make([]atomic.Int64, len(urls)), refusal: refusal, now: time.Now,
	}, nil
}

// Len is the number of addresses.
func (e *Endpoints) Len() int { return len(e.hosts) }

// Index is the position of the address requests go to now.
func (e *Endpoints) Index() int { return int(e.cur.Load()) }

// Use makes address i the current one.
func (e *Endpoints) Use(i int) { e.cur.Store(int64(i)) }

// Advance moves off address from to the next one, only when from is still
// current. Concurrent callers that saw the same failure move it once.
func (e *Endpoints) Advance(from int) {
	e.cur.CompareAndSwap(int64(from), int64((from+1)%len(e.hosts)))
}

// MarkQuorate records that address i reported quorum at the given time.
func (e *Endpoints) MarkQuorate(i int, at time.Time) { e.quorate[i].Store(at.UnixNano()) }

// ClearQuorum forgets the quorum result of address i.
func (e *Endpoints) ClearQuorum(i int) { e.quorate[i].Store(0) }

// Quorate reports whether address i has a positive quorum result no older
// than QuorumFresh.
func (e *Endpoints) Quorate(i int) bool {
	at := e.quorate[i].Load()
	return at != 0 && e.now().Sub(time.Unix(0, at)) <= QuorumFresh
}

// Transport is the shared transport that dials the addresses.
func (e *Endpoints) Transport() *http.Transport { return e.base }

// RoundTrip implements http.RoundTripper.
func (e *Endpoints) RoundTrip(req *http.Request) (*http.Response, error) {
	order := e.order(req.Context())
	read := req.Method == http.MethodGet
	began := time.Now()
	var err error
	sent, refused := 0, 0
	for n, idx := range order {
		if sent > 0 && time.Since(began) > FailoverBudget {
			break
		}
		if !read && !e.Quorate(idx) {
			refused++
			continue
		}
		if sent > 0 && req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return nil, errors.Join(err, errors.New("request body cannot be replayed"))
			}
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, fmt.Errorf("replay request body: %w", bodyErr)
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
		sent++
		last := n == len(order)-1
		resp, connected, rtErr := e.attempt(req, idx, read && !last)
		if rtErr == nil {
			return resp, nil
		}
		err = rtErr
		if req.Context().Err() != nil || connected && !read {
			return nil, err
		}
		if len(order) > 1 {
			e.Advance(idx)
		}
	}
	if sent == 0 {
		return nil, errors.Join(e.refusal, closeBody(req))
	}
	if refused > 0 {
		return nil, errors.Join(e.refusal, err)
	}
	return nil, fmt.Errorf("all %d addresses failed: %w", sent, err)
}

// order is the addresses to try: the pinned one, or all from the current.
func (e *Endpoints) order(ctx context.Context) []int {
	if i, ok := ctx.Value(pinnedKey{}).(int); ok && i >= 0 && i < len(e.hosts) {
		return []int{i}
	}
	start := e.Index()
	order := make([]int, len(e.hosts))
	for k := range order {
		order[k] = (start + k) % len(e.hosts)
	}
	return order
}

// attempt sends req to address idx. connected reports whether a connection
// was obtained, so bytes may have reached the server.
func (e *Endpoints) attempt(req *http.Request, idx int, bounded bool) (resp *http.Response, connected bool, err error) {
	var got atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { got.Store(true) }}
	ctx, cancel := context.WithCancel(httptrace.WithClientTrace(req.Context(), trace))
	var timer *time.Timer
	if bounded {
		timer = time.AfterFunc(AttemptHeaderTimeout, cancel)
	}
	out := req.Clone(ctx)
	out.URL.Scheme, out.URL.Host, out.Host = "https", e.hosts[idx], ""
	resp, err = e.base.RoundTrip(out)
	timedOut := timer != nil && !timer.Stop()
	switch {
	case err != nil:
		cancel()
		if timedOut && req.Context().Err() == nil {
			err = fmt.Errorf("no response headers within %s: %w", AttemptHeaderTimeout, err)
		}
		return nil, got.Load(), err
	case timedOut:
		cancel()
		closeErr := resp.Body.Close()
		return nil, got.Load(), errors.Join(
			fmt.Errorf("no response headers within %s", AttemptHeaderTimeout), closeErr)
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, got.Load(), nil
}

// cancelOnClose ends the attempt's context when the caller closes the body.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	defer c.cancel()
	if err := c.ReadCloser.Close(); err != nil {
		return fmt.Errorf("close response body: %w", err)
	}
	return nil
}

func closeBody(req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	if err := req.Body.Close(); err != nil {
		return fmt.Errorf("close request body: %w", err)
	}
	return nil
}
