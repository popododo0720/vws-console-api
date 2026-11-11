package iamclient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient/iamtest"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

func TestConsoleSessionsSharedAcrossInstancesAndRestart(t *testing.T) {
	for _, user := range []string{"bob", "root"} {
		t.Run(user, func(t *testing.T) {
			endpoint, store := iamtest.Serve(t)
			newInstance := func() (http.Handler, func()) {
				conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
			logins, remaining := store.Snapshot()
			if len(logins) != 1 || logins[0] != user || remaining != 0 {
				t.Fatalf("IAM login calls %v, remaining sessions %d", logins, remaining)
			}
		})
	}
}
