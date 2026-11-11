package iamclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

// The AuthService owns these tokens independently of any console client.
type sharedSessions struct {
	iamv1.UnimplementedAuthServiceServer
	mu       sync.Mutex
	tokens   map[string]*iamv1.Principal
	sequence int
	logins   []string
}

func (s *sharedSessions) Login(_ context.Context, r *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
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
	s.sequence++
	token := fmt.Sprintf("session-%d", s.sequence)
	s.tokens[token] = p
	s.logins = append(s.logins, r.GetUserName())
	return &iamv1.LoginResponse{
		SessionToken: token, Principal: p, ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *sharedSessions) ValidateSession(
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

func (s *sharedSessions) Logout(_ context.Context, r *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, r.GetSessionToken())
	return &iamv1.LogoutResponse{}, nil
}

func TestConsoleSessionsSharedAcrossInstancesAndRestart(t *testing.T) {
	for _, user := range []string{"bob", "root"} {
		t.Run(user, func(t *testing.T) {
			store := &sharedSessions{tokens: make(map[string]*iamv1.Principal)}
			lis := bufconn.Listen(1 << 20)
			g := grpc.NewServer()
			iamv1.RegisterAuthServiceServer(g, store)
			go func() { _ = g.Serve(lis) }()
			t.Cleanup(g.Stop)
			newInstance := func() (http.Handler, func()) {
				conn, err := grpc.NewClient("passthrough:///shared-iam",
					grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
						return lis.DialContext(ctx)
					}),
					grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					t.Fatal(err)
				}
				closeClient := sync.OnceFunc(func() {
					if err := conn.Close(); err != nil {
						t.Error(err)
					}
				})
				t.Cleanup(closeClient)
				remote := New(conn, Options{})
				root := iam.NewStatic("AKIDEXAMPLE", "secret", account(t))
				if err := root.SetPassword(t.Context(), "correct horse 1"); err != nil {
					t.Fatal(err)
				}
				return console.New(console.Config{
					Service: cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()}),
					IAM:     iam.WithRootKey(root, remote),
				}), closeClient
			}
			first, closeFirst := newInstance()
			second, _ := newInstance()
			instances := []http.Handler{first, second}
			var mu sync.Mutex
			next := 0
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				index := next % len(instances)
				next++
				h := instances[index]
				mu.Unlock()
				w.Header().Set("X-Test-Instance", fmt.Sprint(index))
				h.ServeHTTP(w, r)
			}))
			t.Cleanup(proxy.Close)
			client := proxy.Client()
			request := func(
				method, path, body string, cookie *http.Cookie, csrf string, instance, want int,
			) []*http.Cookie {
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
				return resp.Cookies()
			}
			login := request(http.MethodPost, "/api/v1/auth/login",
				fmt.Sprintf(`{"account":"123456789012","userName":%q,"password":"correct horse 1"}`, user),
				nil, "", 0, http.StatusOK)
			var cookie *http.Cookie
			var csrf string
			for _, c := range login {
				switch c.Name {
				case console.SessionCookie:
					cookie = c
				case console.CSRFCookie:
					csrf = c.Value
				}
			}
			if cookie == nil || csrf == "" {
				t.Fatal("login did not set session and CSRF cookies")
			}
			request(http.MethodGet, "/api/v1/auth/session", "", cookie, "", 1, http.StatusOK)
			closeFirst()
			restarted, _ := newInstance()
			mu.Lock()
			instances[0] = restarted
			mu.Unlock()
			request(http.MethodGet, "/api/v1/auth/session", "", cookie, "", 0, http.StatusOK)
			request(http.MethodPost, "/api/v1/auth/logout", "", cookie, csrf, 1, http.StatusNoContent)
			request(http.MethodGet, "/api/v1/auth/session", "", cookie, "", 0, http.StatusUnauthorized)
			request(http.MethodGet, "/api/v1/auth/session", "", cookie, "", 1, http.StatusUnauthorized)
			store.mu.Lock()
			defer store.mu.Unlock()
			if len(store.logins) != 1 || store.logins[0] != user || len(store.tokens) != 0 {
				t.Fatalf("IAM login calls %v, remaining sessions %d", store.logins, len(store.tokens))
			}
		})
	}
}
