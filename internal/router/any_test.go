package router_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/router"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

type origin struct {
	mu    sync.Mutex
	calls int
	got   []*http.Request
	body  [][]byte
}

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	o.got, o.body = append(o.got, r), append(o.body, b)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// stack is the router with the generic forward handler in front of a fake
// AWS proxy on a unix socket, the only way out of the global API.
func stack(t *testing.T, authz iam.Authorizer, cred sigv4.Credential, logs io.Writer) (http.Handler, *origin) {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "r794-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	o := &origin{}
	server := &http.Server{Handler: o, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	f := router.NewForwarder(socket, audit.New(logs))
	t.Cleanup(f.Close)
	catalog := backend.NewStaticRegions(nil, []backend.AWSAccount{
		{ID: "987654321098", AllowedRegions: []string{"ap-northeast-2"}},
	})
	auth := iam.Authenticator(iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account))
	verifier := func(s sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{Service: s, Regions: catalog, Auth: auth})
	}
	return router.New(router.Config{
		Regions: catalog, Error: ec2query.WriteError,
		Local:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("AWS request reached local") }),
		Forward: f.Any(router.ForwardConfig{Verifier: verifier, Authorizer: authz, Error: ec2query.WriteError}),
	}), o
}

func caller(t *testing.T) (sigv4.Credential, *iam.Static) {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return sigv4.Credential{AccessKey: "AKIDCALLER", Secret: "caller-secret", Account: account},
		iam.NewStatic("AKIDCALLER", "caller-secret", account)
}

func dynamoPut(t *testing.T, cred sigv4.Credential, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
	if err := sigv4.SignHeaders(r, cred, "dynamodb", "ap-northeast-2", time.Now(), "x-amz-target"); err != nil {
		t.Fatal(err)
	}
	return r
}

type denyAll struct{ asked []string }

func (d *denyAll) Authorize(_ context.Context, req iam.Request) (iam.Decision, error) {
	d.asked = append(d.asked, req.Action)
	return iam.Decision{}, nil
}

func TestIAMDenyReachesNoOrigin(t *testing.T) {
	cred, _ := caller(t)
	deny := &denyAll{}
	var logs bytes.Buffer
	h, o := stack(t, deny, cred, &logs)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, dynamoPut(t, cred, []byte(`{"TableName":"t"}`)))
	if res.Code != http.StatusForbidden {
		t.Fatalf("deny answered %d %s, want 403", res.Code, res.Body)
	}
	if o.calls != 0 {
		t.Fatalf("proxy received %d requests after an IAM deny", o.calls)
	}
	if len(deny.asked) != 1 || deny.asked[0] != "dynamodb:PutItem" {
		t.Fatalf("authorized %v, want [dynamodb:PutItem]", deny.asked)
	}
	if !strings.Contains(logs.String(), `"result":"denied"`) || !strings.Contains(logs.String(), `"action":"PutItem"`) {
		t.Fatalf("deny not audited: %s", logs.String())
	}
}

func TestForwardedBodyIsByteIdentical(t *testing.T) {
	cred, allow := caller(t)
	var logs bytes.Buffer
	h, o := stack(t, allow, cred, &logs)
	body := []byte("{\"TableName\":\"t\",\"Item\":{\"k\":{\"B\":\"\x00\xff\r\n\"}}}  \n")
	want := sha256.Sum256(body)
	req := dynamoPut(t, cred, body)
	req.Header.Set("X-Vws-Account", "000000000000")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || o.calls != 1 {
		t.Fatalf("forwarded call answered %d %s; proxy calls %d", res.Code, res.Body, o.calls)
	}
	if got := sha256.Sum256(o.body[0]); got != want {
		t.Fatalf("forwarded body sha256 %x, received %x", got, want)
	}
	r := o.got[0]
	if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.PutItem" ||
		r.Header.Get("Content-Type") != "application/x-amz-json-1.0" ||
		r.Header.Get("X-Vws-Target-Service") != "dynamodb" ||
		r.Header.Get("X-Vws-Target-Region") != "ap-northeast-2" ||
		r.Header.Get("X-Vws-Account") != "123456789012" ||
		r.Header.Get("Authorization") != "" {
		t.Fatalf("forwarding metadata: %v", r.Header)
	}
	if line := logs.String(); !strings.Contains(line, `"service":"dynamodb"`) ||
		!strings.Contains(line, `"result":"accepted"`) {
		t.Fatalf("forwarded change not audited: %s", line)
	}
}
