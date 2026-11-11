package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

// These sessions belong to the AuthService, not either command instance.
type commandSessions struct {
	iamv1.UnimplementedAuthServiceServer
	mu     sync.Mutex
	tokens map[string]*iamv1.Principal
	logins []string
}

func (s *commandSessions) Login(_ context.Context, r *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.GetProject() != "123456789012" || r.GetPassword() != "correct horse 1" ||
		(r.GetUserName() != "bob" && r.GetUserName() != "root") {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	p := &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Project: r.GetProject(),
		Arn: "arn:vws:iam::123456789012:user/bob", UniqueId: "AIDABOB",
	}
	if r.GetUserName() == "root" {
		p.Type, p.Arn, p.UniqueId = iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT,
			"arn:vws:iam::123456789012:root", r.GetProject()
	}
	s.logins = append(s.logins, r.GetUserName())
	token := fmt.Sprintf("session-%d", len(s.logins))
	s.tokens[token] = p
	return &iamv1.LoginResponse{
		SessionToken: token, Principal: p, ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *commandSessions) ValidateSession(
	_ context.Context, r *iamv1.ValidateSessionRequest,
) (*iamv1.ValidateSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.tokens[r.GetSessionToken()]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	return &iamv1.ValidateSessionResponse{
		Principal: p, ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *commandSessions) Logout(_ context.Context, r *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, r.GetSessionToken())
	return &iamv1.LogoutResponse{}, nil
}

func TestShippedCommandSharesConsoleSessions(t *testing.T) {
	clearCredentialEnv(t)
	store := &commandSessions{tokens: make(map[string]*iamv1.Principal)}
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	iamv1.RegisterAuthServiceServer(g, store)
	grpcDone := make(chan error, 1)
	go func() { grpcDone <- g.Serve(lis) }()
	t.Cleanup(func() {
		g.Stop()
		select {
		case err := <-grpcDone:
			if err != nil {
				t.Errorf("AuthService: %v", err)
			}
		case <-time.After(smokeTimeout):
			t.Error("AuthService did not stop")
		}
	})

	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	var mu sync.Mutex
	var instances [2]*httputil.ReverseProxy
	next := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		index := next % len(instances)
		next++
		target := instances[index]
		mu.Unlock()
		w.Header().Set("X-Test-Instance", fmt.Sprint(index))
		target.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	setInstance := func(index int, addr string) {
		target, err := url.Parse("http://" + addr)
		if err != nil {
			t.Fatal(err)
		}
		p := httputil.NewSingleHostReverseProxy(target)
		p.Transport = transport
		mu.Lock()
		instances[index] = p
		mu.Unlock()
	}
	first, stopFirst := startSharedCommand(t, lis.Addr().String(), proxy.URL)
	second, _ := startSharedCommand(t, lis.Addr().String(), proxy.URL)
	setInstance(0, first.console)
	setInstance(1, second.console)
	client := proxy.Client()
	client.Timeout = smokeTimeout
	request := func(
		method, path, body string, cookie *http.Cookie, csrf string, instance, want int,
	) ([]*http.Cookie, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, proxy.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", proxy.URL)
		req.Header.Set(console.CSRFHeader, csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("X-Test-Instance") != fmt.Sprint(instance) || resp.StatusCode != want {
			t.Fatalf("%s %s: instance %s status %d, want instance %d status %d: %s",
				method, path, resp.Header.Get("X-Test-Instance"), resp.StatusCode, instance, want, data)
		}
		return resp.Cookies(), data
	}
	type session struct {
		user   string
		cookie *http.Cookie
		csrf   string
	}
	checkSession := func(s session, instance int) {
		t.Helper()
		_, data := request(http.MethodGet, "/api/v1/auth/session", "", s.cookie, "", instance, http.StatusOK)
		var body struct {
			Principal string `json:"principal"`
			Root      bool   `json:"root"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		want := "arn:aws:iam::123456789012:user/" + s.user
		if s.user == "root" {
			want = "arn:aws:iam::123456789012:root"
		}
		if body.Principal != want || body.Root != (s.user == "root") {
			t.Fatalf("instance %d: wrong identity for %s: %s", instance, s.user, data)
		}
	}
	for i := range instances {
		request(http.MethodGet, "/api/v1/auth/session", "",
			&http.Cookie{Name: console.SessionCookie, Value: "unknown-session"}, "", i, http.StatusUnauthorized)
	}
	var sessions []session
	for _, user := range []string{"root", "bob"} {
		cookies, _ := request(http.MethodPost, "/api/v1/auth/login",
			fmt.Sprintf(`{"account":"123456789012","userName":%q,"password":"correct horse 1"}`, user),
			nil, "", 0, http.StatusOK)
		s := session{user: user}
		for _, c := range cookies {
			switch c.Name {
			case console.SessionCookie:
				s.cookie = c
			case console.CSRFCookie:
				s.csrf = c.Value
			}
		}
		if s.cookie == nil || s.csrf == "" {
			t.Fatalf("%s login did not set session and CSRF cookies", user)
		}
		checkSession(s, 1)
		sessions = append(sessions, s)
	}
	transport.CloseIdleConnections()
	stopFirst()
	restarted, _ := startSharedCommand(t, lis.Addr().String(), proxy.URL)
	setInstance(0, restarted.console)
	for _, s := range sessions {
		checkSession(s, 0)
		checkSession(s, 1)
	}
	for _, s := range sessions {
		request(http.MethodPost, "/api/v1/auth/logout", "", s.cookie, s.csrf, 0, http.StatusNoContent)
		request(http.MethodGet, "/api/v1/auth/session", "", s.cookie, "", 1, http.StatusUnauthorized)
		// Replaying a revoked token must also fail on the instance that revoked it.
		request(http.MethodGet, "/api/v1/auth/session", "", s.cookie, "", 0, http.StatusUnauthorized)
		request(http.MethodGet, "/api/v1/auth/session", "", s.cookie, "", 1, http.StatusUnauthorized)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if strings.Join(store.logins, ",") != "root,bob" || len(store.tokens) != 0 {
		t.Fatalf("AuthService logins %v, remaining sessions %d", store.logins, len(store.tokens))
	}
}

func startSharedCommand(t *testing.T, endpoint, origin string) (fakeProcess, func()) {
	t.Helper()
	for attempt := 0; attempt < smokeAttempts; attempt++ {
		// Hold both reservations together so the OS cannot return the same port twice.
		listeners := make([]net.Listener, 0, 2)
		for range 2 {
			l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				for _, reserved := range listeners {
					reserved.Close()
				}
				t.Fatal(err)
			}
			listeners = append(listeners, l)
		}
		p := fakeProcess{
			console: listeners[0].Addr().String(), ops: listeners[1].Addr().String(),
			ec2: "127.0.0.1:0", s3: "127.0.0.1:0", iam: "127.0.0.1:0",
		}
		for _, l := range listeners {
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		var runErr error
		go func() {
			runErr = run(ctx, append(p.args(), "-iam=grpc", "-iam-endpoint="+endpoint, "-console-origins="+origin))
			close(done)
		}()
		stop := sync.OnceFunc(func() {
			cancel()
			select {
			case <-done:
				if runErr != nil && !errors.Is(runErr, syscall.EADDRINUSE) {
					t.Errorf("command: %v", runErr)
				}
			case <-time.After(smokeTimeout):
				t.Error("command did not stop")
			}
		})
		err := waitSharedCommand(t.Context(), p, done)
		if err == nil {
			t.Cleanup(stop)
			return p, stop
		}
		stop()
		select {
		case <-done:
			if !errors.Is(runErr, syscall.EADDRINUSE) {
				t.Fatalf("command readiness: %v; run: %v", err, runErr)
			}
		default:
			t.Fatal("command did not finish after readiness failure")
		}
	}
	t.Fatalf("command could not bind after %d attempts", smokeAttempts)
	return fakeProcess{}, nil
}

func waitSharedCommand(ctx context.Context, p fakeProcess, done <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(ctx, smokeTimeout)
	defer cancel()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, probe := range []struct {
		url  string
		want int
	}{
		{"http://" + p.ops + "/readyz", http.StatusOK},
		{"http://" + p.console + "/api/v1/auth/session", http.StatusUnauthorized},
	} {
		for {
			select {
			case <-done:
				return errors.New("command stopped before readiness")
			case <-ctx.Done():
				return fmt.Errorf("readiness %s: %w", probe.url, ctx.Err())
			default:
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, err = io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
			if resp.StatusCode == probe.want {
				break
			}
		}
	}
	return nil
}
