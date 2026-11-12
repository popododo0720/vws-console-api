package iamclient

import (
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// unavailableBound is the longest a request may wait on vws-iam: every
// attempt of a retried call under CallTimeout, plus its backoff.
const unavailableBound = MaxAttempts*CallTimeout + time.Second

// getRole is a fresh form each call: queryCall sets Version on it.
func getRole() url.Values { return url.Values{"Action": {"GetRole"}, "RoleName": {"deploy"}} }

// expectUnavailable serves form and wants 503 ServiceUnavailable, without
// vws-iam's wording, within unavailableBound.
func expectUnavailable(t *testing.T, h http.Handler, form url.Values) {
	t.Helper()
	start := time.Now()
	rec := queryCall(t, h, form)
	if took := time.Since(start); took > unavailableBound {
		t.Errorf("answered after %v, want at most %v", took, unavailableBound)
	}
	expect(t, rec, http.StatusServiceUnavailable, "<Code>ServiceUnavailable</Code>")
}

// A vws-iam that is stopped, accepts and never answers, or hangs on the one
// call the action needs is 503 ServiceUnavailable within a bounded time,
// never a 500 or a hang (#700).
func TestStoppedOrHangingIAMIsServiceUnavailable(t *testing.T) {
	t.Run("stopped endpoint", func(t *testing.T) {
		t.Parallel()
		lis, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := lis.Addr().String()
		if err := lis.Close(); err != nil {
			t.Fatal(err)
		}
		expectUnavailable(t, queryHandler(dialed(t, addr)), getRole())
	})
	t.Run("endpoint that accepts and never answers", func(t *testing.T) {
		t.Parallel()
		lis, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var held []net.Conn
		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				held = append(held, conn)
				mu.Unlock()
			}
		}()
		t.Cleanup(func() {
			_ = lis.Close()
			mu.Lock()
			defer mu.Unlock()
			for _, c := range held {
				_ = c.Close()
			}
		})
		expectUnavailable(t, queryHandler(dialed(t, lis.Addr().String())), getRole())
	})
	t.Run("GetRole that never answers", func(t *testing.T) {
		t.Parallel()
		h, s := queryHarness(t)
		s.getRoleHang = true
		expectUnavailable(t, h, getRole())
	})
}

// A vws-iam timeout or outage on an admin call is 503, as on Authenticate
// and Authorize; an internal error stays a 500 and echoes nothing (#700).
func TestIAMTimeoutIsServiceUnavailable(t *testing.T) {
	for _, tc := range []struct {
		code   codes.Code
		status int
		part   string
	}{
		{codes.DeadlineExceeded, http.StatusServiceUnavailable, "<Code>ServiceUnavailable</Code>"},
		{codes.Unavailable, http.StatusServiceUnavailable, "<Code>ServiceUnavailable</Code>"},
		{codes.Canceled, http.StatusServiceUnavailable, "<Code>ServiceUnavailable</Code>"},
		{codes.Internal, http.StatusInternalServerError, "<Code>ServiceFailure</Code>"},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			h, s := queryHarness(t)
			s.getRoleErr = status.Error(tc.code, vwsIAMMsg)
			expect(t, queryCall(t, h, getRole()), tc.status, tc.part)
		})
	}
}

// A vws-iam that comes back answers the next request without a console-api
// restart, and a request repeated while it is down gets the same 503 (#700).
func TestIAMBackFromAnOutageAnswersTheRetry(t *testing.T) {
	h, s := queryHarness(t)
	s.getRoleRes = &iamv1.Role{
		Name:   "projects/123456789012/roles/deploy",
		Spec:   &iamv1.RoleSpec{Path: "/"},
		Status: &iamv1.RoleStatus{Arn: "arn:vws:iam::123456789012:role/deploy", UniqueId: "AROADEPLOY0000000001"},
	}
	s.getRoleErr = status.Error(codes.Unavailable, vwsIAMMsg)
	expectUnavailable(t, h, getRole())
	expectUnavailable(t, h, getRole())
	s.mu.Lock()
	s.getRoleErr = nil
	s.mu.Unlock()
	expect(t, queryCall(t, h, getRole()), http.StatusOK, "<RoleName>deploy</RoleName>")
}

// dialed is a Dial client for addr, closed with the test.
func dialed(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
