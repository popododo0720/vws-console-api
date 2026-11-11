package regionapi

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
)

func TestServerServeRequiresTLS(t *testing.T) {
	cert, clientCert, pool := certificates(t)
	h, err := New(config(fake.New(fake.Options{}).Set()))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer("", h, cert, pool)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+ln.Addr().String()+"/internal/v1/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err == nil {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plaintext reached region handler")
		}
	}
	for _, authenticated := range []bool{false, true} {
		config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
		if authenticated {
			config.Certificates = []tls.Certificate{clientCert}
		}
		transport := &http.Transport{TLSClientConfig: config}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: time.Second}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			"https://"+ln.Addr().String()+"/internal/v1/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			if authenticated {
				t.Fatal(err)
			}
			continue
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if !authenticated || resp.StatusCode != http.StatusOK {
			t.Fatalf("authentication=%v status=%d", authenticated, resp.StatusCode)
		}
	}
}
