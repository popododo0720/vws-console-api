package pveclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
)

// Endpoints is the http.RoundTripper of a client that talks to one cluster
// through several node addresses. It keeps one ordered list and one current
// index. Every request goes to the current address; when that address fails
// the index moves to the next one, wrapping around.
//
// A request moves on only when the failure proves the next address cannot
// double-apply it. A GET may move after any transport error, since reading
// twice changes nothing. Any other method moves only when no connection to
// the address was ever obtained: a dial or TLS handshake failure, before the
// first byte of the request was written. Once a connection exists, a failed
// write returns its error and the caller reconciles through PVE (task UPID
// and launch marker) instead of sending the request to a second node.
//
// Requests go only to the registered addresses, never follow a redirect to
// another host and never carry the Authorization header anywhere else. TLS
// verifies each address against the CA of the base transport under that
// address's own host name.
type Endpoints struct {
	base  *http.Transport
	hosts []string // scheme-less origins, in registration order
	cur   atomic.Int64
}

// NewEndpoints returns the failover transport over base for urls, which must
// be HTTPS origins without a path.
func NewEndpoints(base *http.Transport, urls []string) (*Endpoints, error) {
	if base == nil || len(urls) == 0 {
		return nil, errors.New("pveclient: endpoints need a transport and at least one address")
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
	return &Endpoints{base: base, hosts: hosts}, nil
}

// Len is the number of addresses.
func (e *Endpoints) Len() int { return len(e.hosts) }

// Index is the position of the address requests go to now.
func (e *Endpoints) Index() int { return int(e.cur.Load()) }

// Advance moves off address from to the next one, only when from is still
// current. Concurrent callers that saw the same failure move it once.
func (e *Endpoints) Advance(from int) {
	e.cur.CompareAndSwap(int64(from), int64((from+1)%len(e.hosts)))
}

// Transport is the shared transport that dials the addresses.
func (e *Endpoints) Transport() *http.Transport { return e.base }

// RoundTrip implements http.RoundTripper.
func (e *Endpoints) RoundTrip(req *http.Request) (*http.Response, error) {
	start := int(e.cur.Load())
	var err error
	for attempt := range e.Len() {
		idx := (start + attempt) % e.Len()
		var connected atomic.Bool
		trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}
		out := req.Clone(httptrace.WithClientTrace(req.Context(), trace))
		out.URL.Scheme, out.URL.Host, out.Host = "https", e.hosts[idx], ""
		if attempt > 0 && req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return nil, errors.Join(err, errors.New("request body cannot be replayed"))
			}
			if out.Body, err = req.GetBody(); err != nil {
				return nil, fmt.Errorf("replay request body: %w", err)
			}
		}
		resp, rtErr := e.base.RoundTrip(out)
		if rtErr == nil {
			return resp, nil
		}
		err = rtErr
		if req.Context().Err() != nil || connected.Load() && !readsOnly(req.Method) {
			return nil, err
		}
		e.Advance(idx)
	}
	return nil, fmt.Errorf("all %d addresses failed: %w", e.Len(), err)
}

func readsOnly(method string) bool {
	return strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead)
}
