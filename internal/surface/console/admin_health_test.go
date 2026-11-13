package console

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAdminHealthFailureMessagesAreSafe(t *testing.T) {
	e, _ := adminFixture(t)
	var logs bytes.Buffer
	e.h.(*handler).log = slog.New(slog.NewJSONHandler(&logs, nil))
	const endpoint = "https://endpoint-canary:8443"
	const certPath = "/private/cert-path-canary.pem"
	const keyPath = "/private/key-path-canary.pem"
	dial := &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{Port: 8443},
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("credential-canary " + endpoint + " " + certPath + " " + keyPath), "region transport failed"},
		{fmt.Errorf("%s: %w", endpoint, &resource.Error{Code: resource.CodeUnavailable, Message: "not ready"}), "not ready"},
		{
			fmt.Errorf("%s: %w", endpoint, (&resource.Error{
				Code: resource.CodeUnavailable, Message: `pool "vws-default": missing Pool.Audit`,
			}).WithCause(errors.New("credential-canary"))),
			`pool \"vws-default\": missing Pool.Audit`,
		},
		{
			&resource.Error{Code: resource.CodeUnavailable, Message: "registration self-check failed: storages"},
			"registration self-check failed: storages",
		},
		{
			&resource.Error{Code: resource.CodeUnavailable, Message: "credential-canary " + endpoint},
			"region transport failed",
		},
		{fmt.Errorf("%s credential-canary: %w", endpoint, context.DeadlineExceeded), "deadline exceeded"},
		{fmt.Errorf("%s credential-canary: %w", endpoint, dial), "dial: connection refused"},
		{&tls.CertificateVerificationError{Err: errors.New(certPath + " credential-canary")}, "TLS handshake failed"},
		{
			&RegionMTLSConfigError{Err: &os.PathError{Op: "open", Path: certPath, Err: os.ErrNotExist}},
			"region mTLS configuration failed",
		},
		{&RegionMTLSConfigError{Err: errors.New(keyPath + " credential-canary")}, "region mTLS configuration failed"},
	} {
		e.h.(*handler).regionStatus = func(context.Context, string) (resource.RegionStatus, error) {
			return resource.RegionStatus{}, tc.err
		}
		rec := e.do(t, "GET", "/api/v1/admin/regions/pve-lab-1/health", "",
			map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), tc.want) ||
			strings.Contains(rec.Body.String(), "credential-canary") ||
			strings.Contains(rec.Body.String(), endpoint) || strings.Contains(rec.Body.String(), certPath) ||
			strings.Contains(rec.Body.String(), keyPath) {
			t.Fatalf("unsafe or missing health failure: %d %s", rec.Code, rec.Body)
		}
	}
	if !strings.Contains(logs.String(), "credential file missing") ||
		strings.Contains(logs.String(), "credential-canary") {
		t.Fatalf("missing or unsafe server-side detail: %s", logs.String())
	}
}
