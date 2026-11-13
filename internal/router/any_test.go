package router_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	"github.com/popododo0720/vws-console-api/internal/proxy"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/router"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

type oneAccount struct{}

func (oneAccount) Account(context.Context, string, string) (proxy.Account, error) {
	return proxy.Account{
		ID: "987654321098", RoleARN: "arn:aws:iam::987654321098:role/vws", ExternalID: "external",
		Regions: []string{"ap-northeast-2"},
	}, nil
}

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
	w.Header().Set("X-Origin", "aws")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"arn":"arn:aws:dynamodb:ap-northeast-2:987654321098:table/t"}`)
}

// stack is the global API (router with the generic forward handler) in front
// of the real AWS proxy on a unix socket, in front of a fake STS and origin.
func stack(t *testing.T, authz iam.Authorizer, cred sigv4.Credential, logs io.Writer) (http.Handler, *origin) {
	t.Helper()
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>`+
			`<AccessKeyId>session-key</AccessKeyId><SecretAccessKey>session-secret</SecretAccessKey>`+
			`<SessionToken>session-token</SessionToken><Expiration>%s</Expiration>`+
			`</Credentials></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)
	o := &origin{}
	aws := httptest.NewServer(o)
	t.Cleanup(aws.Close)
	p, err := proxy.New(oneAccount{}, sigv4.Credential{AccessKey: "source-key", Secret: "source-secret"},
		sts.URL, "us-east-1", aws.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ServiceEndpoint(aws.URL); err != nil {
		t.Fatal(err)
	}
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
	server := &http.Server{Handler: p, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
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
		t.Fatalf("origin received %d requests after an IAM deny", o.calls)
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
	res := httptest.NewRecorder()
	h.ServeHTTP(res, dynamoPut(t, cred, body))
	if res.Code != http.StatusOK || res.Header().Get("X-Origin") != "aws" ||
		res.Body.String() != `{"arn":"arn:aws:dynamodb:ap-northeast-2:987654321098:table/t"}` {
		t.Fatalf("forwarded call answered %d %v %s", res.Code, res.Header(), res.Body)
	}
	if o.calls != 1 {
		t.Fatalf("origin received %d requests, want 1", o.calls)
	}
	if got := sha256.Sum256(o.body[0]); got != want {
		t.Fatalf("forwarded body sha256 %x, received %x", got, want)
	}
	r := o.got[0]
	if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.PutItem" ||
		r.Header.Get("Content-Type") != "application/x-amz-json-1.0" ||
		r.Header.Get("X-Amz-Security-Token") != "session-token" ||
		!strings.Contains(r.Header.Get("Authorization"), "Credential=session-key/") ||
		!strings.Contains(r.Header.Get("Authorization"), "/ap-northeast-2/dynamodb/aws4_request") ||
		!strings.Contains(r.Header.Get("Authorization"), "x-amz-target") ||
		r.Header.Get("X-Vws-Account") != "" {
		t.Fatalf("origin request not re-signed for dynamodb: %v", r.Header)
	}
	if line := logs.String(); !strings.Contains(line, `"service":"dynamodb"`) ||
		!strings.Contains(line, `"result":"accepted"`) {
		t.Fatalf("forwarded change not audited: %s", logs.String())
	}
}
