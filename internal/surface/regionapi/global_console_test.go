package regionapi

//vws:unseeded concurrent TLS and websocket handshakes own crypto/rand through connection shutdown

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/proxmoxtest"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

type consoleTransport struct {
	*Client
	calls atomic.Int32
	opens atomic.Int32
}

func (c *consoleTransport) Call(ctx context.Context, service, method string, scope, req, dst any) error {
	c.calls.Add(1)
	return c.Client.Call(ctx, service, method, scope, req, dst)
}

func (c *consoleTransport) OpenConsole(
	ctx context.Context, scope backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	c.calls.Add(1)
	c.opens.Add(1)
	return c.Client.OpenConsole(ctx, scope, id, kind)
}

type consoleCaps struct{ backend.Capabilities }

func (c consoleCaps) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	if region == "us-east-1" {
		return (backend.AllSupported{Kind: resource.RegionKindAWS}).RegionCapabilities(ctx, region)
	}
	return c.Capabilities.RegionCapabilities(ctx, region)
}

func TestGlobalConsoleStreamAndRefusals(t *testing.T) {
	b := proxmoxtest.Console(t)
	scope := testScope(t)
	page, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("PVE inventory: %+v %v", page, err)
	}
	id := page.Items[0].ID
	cfg := config(b.Set())
	cfg.Capabilities, cfg.Region = b, "pve-test-1"
	client, _ := loopback(t, cfg)
	transport := &consoleTransport{Client: client}
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}},
		[]backend.AWSAccount{{AllowedRegions: []string{"us-east-1"}}})
	var resolves atomic.Int32
	set, err := regionset.New(catalog, func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
		resolves.Add(1)
		return transport, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: set, Regions: catalog, Capabilities: consoleCaps{b}})
	owner := iam.NewStatic("access", "secret", scope.Account)
	foreignID, _ := resource.Parse[resource.AccountID]("999999999999")
	foreign := iam.NewStatic("other", "secret", foreignID)
	session := func(root *iam.Static, account resource.AccountID) *http.Cookie {
		t.Helper()
		if err := root.SetPassword(t.Context(), "correct horse 1"); err != nil {
			t.Fatal(err)
		}
		login, err := root.Login(t.Context(), iam.LoginRequest{
			Account: account, UserName: iam.RootUserName, Password: "correct horse 1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: console.SessionCookie, Value: login.Token}
	}
	ownerCookie, foreignCookie := session(owner, scope.Account), session(foreign, foreignID)
	newGlobal := func() *httptest.Server {
		rootCaller := resource.Caller{Account: scope.Account, Root: true, Principal: iam.RootARN(scope.Account)}
		srv := httptest.NewServer(console.New(console.Config{
			Service: svc, Region: "pve-test-1", IAM: iam.WithRoot(owner, foreign),
			Auth: console.BearerTokens{"bearer": rootCaller}, Origins: []string{"https://console.example"},
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	global := newGlobal()
	path := "/api/v1/instances/" + id.String() + "/console"
	for _, tc := range []struct {
		name, query, origin, auth, region string
		cookie                            *http.Cookie
		status                            int
		consoleCalls                      int32
	}{
		{name: "missing kind", cookie: ownerCookie, status: 400},
		{name: "empty kind", query: "kind=", cookie: ownerCookie, status: 400},
		{name: "repeated", query: "kind=vnc&kind=vnc", cookie: ownerCookie, status: 400},
		{name: "unknown", query: "kind=other", cookie: ownerCookie, status: 400},
		{name: "extra", query: "kind=vnc&extra=1", cookie: ownerCookie, status: 400},
		{name: "malformed", query: "kind=vnc;extra=1", cookie: ownerCookie, status: 400},
		{name: "no session", query: "kind=vnc", status: 401},
		{name: "bearer", query: "kind=vnc", auth: "Bearer bearer", status: 401},
		{name: "cross origin", query: "kind=vnc", cookie: ownerCookie, origin: "https://evil.example", status: 403},
		{name: "no origin", query: "kind=vnc", cookie: ownerCookie, origin: "none", status: 403},
		{name: "foreign", query: "kind=vnc", cookie: foreignCookie, status: 404, consoleCalls: 1},
		{name: "aws", query: "kind=vnc", cookie: ownerCookie, region: "us-east-1", status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, opened, resolved := transport.calls.Load(), transport.opens.Load(), resolves.Load()
			origin := tc.origin
			if origin == "" {
				origin = "https://console.example"
			}
			headers := http.Header{"Origin": {origin}}
			if origin == "none" {
				headers.Del("Origin")
			}
			if tc.cookie != nil {
				headers.Set("Cookie", tc.cookie.String())
			}
			if tc.auth != "" {
				headers.Set("Authorization", tc.auth)
			}
			if tc.region != "" {
				headers.Set("X-Vws-Region", tc.region)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, resp, err := websocket.DefaultDialer.DialContext(ctx,
				"ws"+strings.TrimPrefix(global.URL, "http")+path+"?"+tc.query, headers)
			if conn != nil {
				conn.Close()
			}
			if resp == nil {
				t.Fatalf("no HTTP response: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if err == nil || resp.StatusCode != tc.status {
				t.Fatalf("refusal: %d %s %v", resp.StatusCode, body, err)
			}
			if transport.opens.Load() != opened || transport.calls.Load()-before != tc.consoleCalls {
				t.Fatalf("refused request reached console: %s", body)
			}
			if tc.name != "foreign" && resolves.Load() != resolved {
				t.Fatal("refusal resolved a region transport")
			}
			if tc.name == "foreign" && !strings.Contains(string(body), "NotFound") {
				t.Fatalf("foreign response: %s", body)
			}
			if tc.name == "aws" && !strings.Contains(string(body), "use EC2 Instance Connect") {
				t.Fatalf("AWS capability reason: %s", body)
			}
			assertConsolePublic(t, fmt.Sprint(resp.Header, string(body)))
		})
	}
	for _, kind := range []string{"vnc", "serial"} {
		for range 2 {
			// Recreate the global handler to exercise a reconnect without global session state.
			global = newGlobal()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			conn, resp, err := websocket.DefaultDialer.DialContext(ctx,
				"ws"+strings.TrimPrefix(global.URL, "http")+path+"?kind="+kind,
				http.Header{"Cookie": {ownerCookie.String()}, "Origin": {"https://console.example"}})
			if err != nil {
				cancel()
				t.Fatalf("%s upgrade: %v", kind, err)
			}
			assertConsolePublic(t, fmt.Sprint(resp.Header))
			resp.Body.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			typ, banner, err := conn.ReadMessage()
			if err != nil || typ != websocket.BinaryMessage || string(banner) != "RFB 003.008\n" {
				t.Fatalf("%s first stream frame: %d %q %v", kind, typ, banner, err)
			}
			assertConsolePublic(t, string(banner))
			conn.Close()
			cancel()
		}
	}
}

func assertConsolePublic(t *testing.T, response string) {
	t.Helper()
	for _, secret := range []string{
		"fake-secret", "PVEVNC", "vncticket", "vncproxy", "termproxy",
		"X-Vws-Console-Session", `"token"`, `"port"`, ":5900", ":5901",
	} {
		if strings.Contains(strings.ToLower(response), strings.ToLower(secret)) {
			t.Fatalf("console exposed %q: %s", secret, response)
		}
	}
}
