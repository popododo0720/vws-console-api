package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// metricPrefix names every series this process exports. VWS services share
// the vws_ namespace; the component keeps them apart.
const metricPrefix = "vws_console_api_"

// Metrics counts requests per surface. It lives on the Serve call, not in
// package state, so the process stays stateless between runs.
type Metrics struct {
	mu       sync.Mutex
	requests map[requestKey]uint64
	seconds  map[string]float64
	count    map[string]uint64
}

type requestKey struct {
	surface string
	code    int
}

// NewMetrics returns empty counters.
func NewMetrics() *Metrics {
	return &Metrics{
		requests: map[requestKey]uint64{},
		seconds:  map[string]float64{},
		count:    map[string]uint64{},
	}
}

func (m *Metrics) observe(surface string, code int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{surface, code}]++
	m.seconds[surface] += d.Seconds()
	m.count[surface]++
}

// WriteTo writes the Prometheus text exposition format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	m.mu.Lock()
	keys := make([]requestKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].surface != keys[j].surface {
			return keys[i].surface < keys[j].surface
		}
		return keys[i].code < keys[j].code
	})
	surfaces := make([]string, 0, len(m.count))
	for s := range m.count {
		surfaces = append(surfaces, s)
	}
	sort.Strings(surfaces)
	var b []byte
	b = fmt.Appendf(b, "# HELP %shttp_requests_total HTTP requests served, by surface and status code.\n", metricPrefix)
	b = fmt.Appendf(b, "# TYPE %shttp_requests_total counter\n", metricPrefix)
	for _, k := range keys {
		b = fmt.Appendf(b, "%shttp_requests_total{surface=%q,code=\"%d\"} %d\n", metricPrefix, k.surface, k.code, m.requests[k])
	}
	b = fmt.Appendf(b, "# HELP %shttp_request_duration_seconds Time to serve a request, by surface.\n", metricPrefix)
	b = fmt.Appendf(b, "# TYPE %shttp_request_duration_seconds summary\n", metricPrefix)
	for _, s := range surfaces {
		b = fmt.Appendf(b, "%shttp_request_duration_seconds_sum{surface=%q} %s\n", metricPrefix, s, strconv.FormatFloat(m.seconds[s], 'g', -1, 64))
		b = fmt.Appendf(b, "%shttp_request_duration_seconds_count{surface=%q} %d\n", metricPrefix, s, m.count[s])
	}
	m.mu.Unlock()
	n, err := w.Write(b)
	if err != nil {
		return int64(n), fmt.Errorf("write metrics: %w", err)
	}
	return int64(n), nil
}

// instrument counts each request on m. It sits outside wrap, so a recovered
// panic is counted as the 500 it became.
func instrument(m *Metrics, name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &codeRecorder{ResponseWriter: w, code: http.StatusOK}
		defer func() { m.observe(name, rec.code, time.Since(start)) }()
		next.ServeHTTP(rec, r)
	})
}

type codeRecorder struct {
	http.ResponseWriter
	code int
}

func (c *codeRecorder) WriteHeader(code int) {
	c.code = code
	c.ResponseWriter.WriteHeader(code)
}

// opsHandler serves the liveness, readiness, and metrics endpoints. It runs
// on its own listener so no path collides with a bucket name on the object
// surface or with console routes.
func opsHandler(m *Metrics, ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			writeText(w, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, err := m.WriteTo(w)
		RecordFailure(w, err)
	})
	return mux
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, err := io.WriteString(w, body)
	RecordFailure(w, err)
}
