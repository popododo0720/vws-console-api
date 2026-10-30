package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// smokeTimeout is how long the process may take to start or stop on a loaded
// machine. It is not a latency assertion; the requests below are the test.
const smokeTimeout = 30 * time.Second

// smokeAttempts bounds the retry when another process takes a free address
// between freeAddr closing it and the server binding it.
const smokeAttempts = 5

// TestFakeProcessSmoke starts the console-api process with every listener on
// a free address. The compute, network, and storage repositories are not part
// of this module, so -backend=fake stands in for those three processes.
func TestFakeProcessSmoke(t *testing.T) {
	p := startFakeProcess(t)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+p.ops+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, resp.StatusCode)
		}
	}

	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	now := time.Now().UTC()
	ec2 := func(form url.Values) (int, string) {
		t.Helper()
		return signedStatus(t, cred, sigv4.ServiceEC2, now, http.MethodPost,
			"http://"+p.ec2+"/", form.Encode(), "application/x-www-form-urlencoded")
	}

	code, body := ec2(url.Values{"Action": {"CreateVpc"}, "Version": {"2016-11-15"}, "CidrBlock": {"10.50.0.0/16"}})
	if code != http.StatusOK || strings.Contains(body, "InternalError") {
		t.Fatalf("CreateVpc %d %s", code, body)
	}
	code, body = ec2(url.Values{"Action": {"CreateSubnet"}, "Version": {"2016-11-15"}, "CidrBlock": {"10.50.1.0/24"}})
	if code != http.StatusOK || strings.Contains(body, "ClientToken") || strings.Contains(body, "InternalError") {
		t.Fatalf("CreateSubnet %d %s", code, body)
	}
	for _, action := range []string{"DescribeKeyPairs", "DescribeSecurityGroups", "DescribeAddresses", "DescribeSnapshots"} {
		code, body = ec2(url.Values{"Action": {action}, "Version": {"2016-11-15"}})
		if code != http.StatusOK || strings.Contains(body, "InvalidAction") {
			t.Fatalf("%s %d %s", action, code, body)
		}
	}
	code, body = ec2(url.Values{"Action": {"AllocateAddress"}, "Version": {"2016-11-15"}})
	if code != http.StatusOK || strings.Contains(body, "InvalidAction") || !strings.Contains(body, "<allocationId>") {
		t.Fatalf("AllocateAddress %d %s", code, body)
	}

	code, body = signedStatus(t, cred, sigv4.ServiceS3, now, http.MethodPut, "http://"+p.s3+"/build-logs", "", "")
	if code != http.StatusOK {
		t.Fatalf("bucket %d %s", code, body)
	}
	code, body = signedStatus(t, cred, sigv4.ServiceS3, now, http.MethodPut,
		"http://"+p.s3+"/build-logs/a.txt", "hello", "text/plain")
	if code != http.StatusOK || strings.Contains(body, "object field mask") {
		t.Fatalf("put %d %s", code, body)
	}
	code, body = signedStatus(t, cred, sigv4.ServiceS3, now, http.MethodGet, "http://"+p.s3+"/build-logs/a.txt", "", "")
	if code != http.StatusOK || body != "hello" {
		t.Fatalf("get %d %s", code, body)
	}
}

// fakeProcess is the console-api process under test and the address of each
// listener it serves.
type fakeProcess struct {
	console string
	ec2     string
	s3      string
	iam     string
	ops     string
}

func (p fakeProcess) args() []string {
	return []string{
		"-backend=fake",
		"-console-addr=" + p.console,
		"-ec2-addr=" + p.ec2,
		"-s3-addr=" + p.s3,
		"-iam-addr=" + p.iam,
		"-ops-addr=" + p.ops,
	}
}

// startFakeProcess starts the process and waits until every listener answers.
// Another process can take a free address after freeAddr closes it and before
// the server binds it, so a bind failure is retried on fresh addresses
// (issue #437). Any other error is real.
func startFakeProcess(t *testing.T) fakeProcess {
	t.Helper()
	for attempt := 1; attempt <= smokeAttempts; attempt++ {
		p := fakeProcess{
			console: freeAddr(t),
			ec2:     freeAddr(t),
			s3:      freeAddr(t),
			iam:     freeAddr(t),
			ops:     freeAddr(t),
		}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		done := make(chan struct{})
		args := p.args()
		go func() {
			errc <- run(ctx, args)
			close(done)
		}()
		err := waitListening(ctx, []string{p.ec2, p.s3, p.console, p.iam, p.ops}, errc, done)
		if err == nil {
			t.Cleanup(func() {
				// The test client can leave an idle connection it opened but
				// never used. http.Server.Shutdown leaves a connection in
				// StateNew alone until it is five seconds old, so the drain
				// deadline expired and run returned context.DeadlineExceeded
				// (issue #416). Close the client's idle connections first;
				// any error after that is real.
				http.DefaultClient.CloseIdleConnections()
				cancel()
				select {
				case err := <-errc:
					if err != nil {
						t.Errorf("process: %v", err)
					}
				case <-time.After(smokeTimeout):
					t.Errorf("process did not stop")
				}
			})
			return p
		}
		cancel()
		select {
		case <-done:
		case <-time.After(smokeTimeout):
			t.Fatalf("process did not stop after %v", err)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("process: %v", err)
		}
	}
	t.Fatalf("process could not bind after %d attempts", smokeAttempts)
	return fakeProcess{}
}

// waitListening waits until every address accepts a connection. A process
// that stops first ends the wait with its error.
func waitListening(ctx context.Context, addrs []string, errc <-chan error, done <-chan struct{}) error {
	deadline := time.Now().Add(smokeTimeout)
	for _, addr := range addrs {
		for {
			select {
			case <-done:
				if err := <-errc; err != nil {
					return err
				}
				return errors.New("process stopped before its listeners were ready")
			default:
			}
			conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("listen %s: %w", addr, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitListen(t *testing.T, addr string) {
	t.Helper()
	if err := waitListening(t.Context(), []string{addr}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func signedStatus(t *testing.T, cred sigv4.Credential, service sigv4.Service, now time.Time, method, rawURL, body, contentType string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := sigv4.Sign(req, cred, service, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(raw)
}
