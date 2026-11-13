package s3proxy_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/cryptotest"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/s3proxy"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

func registry(t *testing.T) (*store.Registry, *secret.Key, map[string]sigv4.Credential) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 796)
	g := store.New(store.NewMemory())
	k, err := secret.New("test", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]sigv4.Credential{}
	for _, id := range []string{"123456789012", "210987654321"} {
		account, err := resource.Parse[resource.AccountID](id)
		if err != nil {
			t.Fatal(err)
		}
		c := sigv4.Credential{AccessKey: "access-canary-796-" + id, Secret: "secret-canary-796-" + id, Account: account}
		creds[c.AccessKey] = c
		r, err := store.SealRGWKey(k, account, c.AccessKey, c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.RGWKeys().Create(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	return g, k, creds
}

func proxy(t *testing.T, endpoint string, g *store.Registry, k *secret.Key) *s3proxy.Storage {
	t.Helper()
	s, err := s3proxy.New(endpoint, resource.RegionName, g, k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestS3ContractAndLogCanary(t *testing.T) {
	g, k, creds := registry(t)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)
	backendtest.S3(t, func() backend.Set {
		world := fake.New(fake.Options{Entropy: &fake.Sequence{}})
		auth := sigv4.Lookup(func(_ context.Context, access string) (sigv4.Credential, bool) {
			c, ok := creds[access]
			return c, ok
		})
		h := s3rest.New(s3rest.Config{
			Service: cloud.New(cloud.Config{Backends: world.Set()}),
			Verifier: sigv4.NewVerifier(sigv4.Verifier{
				Service: sigv4.ServiceS3, Regions: backend.DefaultRegions(), Auth: auth,
			}),
			Authorizer: allow{},
		})
		server := httptest.NewServer(h)
		t.Cleanup(server.Close)
		return backend.Set{Storage: proxy(t, server.URL, g, k)}
	})
	if strings.Contains(logs.String(), "canary-796") {
		t.Fatal("RGW credentials reached logs")
	}
}

type allow struct{}

func (allow) Authorize(context.Context, iam.Request) (iam.Decision, error) {
	return iam.Decision{Allowed: true}, nil
}

func TestMissingKeyMakesNoOriginCall(t *testing.T) {
	g, k, _ := registry(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	s := proxy(t, server.URL, g, k)
	account, err := resource.Parse[resource.AccountID]("999999999999")
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.Parse[resource.BucketName]("no-key-bucket")
	if err != nil {
		t.Fatal(err)
	}
	sc := backend.Scope{Account: account}
	key, err := resource.Parse[resource.ObjectKey]("object")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, e := s.CreateBucket(t.Context(), sc, name); return e },
		func() error { _, e := s.GetBucket(t.Context(), sc, name); return e },
		func() error { _, e := s.ListBuckets(t.Context(), sc, resource.BucketQuery{}); return e },
		func() error { return s.DeleteBucket(t.Context(), sc, name) },
		func() error {
			_, e := s.PutObject(t.Context(), sc, resource.PutObjectRequest{Bucket: name, Key: key}, http.NoBody)
			return e
		},
		func() error {
			_, _, e := s.GetObject(t.Context(), sc, resource.GetObjectRequest{Bucket: name, Key: key})
			return e
		},
		func() error { return s.DeleteObject(t.Context(), sc, name, key) },
		func() error { _, e := s.ListObjects(t.Context(), sc, resource.ObjectQuery{Bucket: name}); return e },
	} {
		if err := call(); resource.CodeOf(err) != resource.CodePermissionDenied || calls.Load() != 0 {
			t.Fatalf("missing key: %v, origin requests %d", err, calls.Load())
		}
	}
}

func TestMalformedOriginResponses(t *testing.T) {
	g, k, creds := registry(t)
	var sc backend.Scope
	for _, c := range creds {
		sc.Account = c.Account
	}
	for _, body := range []string{"<", "<wrong/>", "<ListAllMyBucketsResult/><extra/>", strings.Repeat("x", (1<<20)+1)} {
		t.Run(strings.SplitN(body, "x", 2)[0], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			_, err := proxy(t, server.URL, g, k).ListBuckets(t.Context(), sc, resource.BucketQuery{})
			if resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("malformed origin: %v", err)
			}
		})
	}
}

func TestOriginCannotRedirectCredentials(t *testing.T) {
	g, k, creds := registry(t)
	var calls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	for _, c := range creds {
		_, err := proxy(t, server.URL, g, k).ListBuckets(
			t.Context(), backend.Scope{Account: c.Account}, resource.BucketQuery{})
		if resource.CodeOf(err) != resource.CodeUnavailable || calls.Load() != 0 {
			t.Fatalf("redirect: %v calls=%d", err, calls.Load())
		}
	}
}

func TestTransientReadsRetryAndCancellation(t *testing.T) {
	g, k, creds := registry(t)
	var sc backend.Scope
	for _, c := range creds {
		sc.Account = c.Account
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "<ListAllMyBucketsResult/>")
	}))
	defer server.Close()
	s := proxy(t, server.URL, g, k)
	if _, err := s.ListBuckets(t.Context(), sc, resource.BucketQuery{}); err != nil || calls.Load() != 3 {
		t.Fatalf("transient retry: %v calls=%d", err, calls.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ListBuckets(ctx, sc, resource.BucketQuery{}); err == nil || calls.Load() != 3 {
		t.Fatalf("canceled request: %v calls=%d", err, calls.Load())
	}
}
