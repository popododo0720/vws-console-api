package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/router"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

type actionAllowlist []string

func (a actionAllowlist) Authorize(_ context.Context, r iam.Request) (iam.Decision, error) {
	return iam.Decision{Allowed: slices.Contains(a, r.Action)}, nil
}

func routedProxy(t *testing.T, p *Proxy, allowed ...string) http.Handler {
	t.Helper()
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "r995-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "p.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: p, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	forward := router.NewForwarder(socket, nil)
	t.Cleanup(forward.Close)
	catalog := backend.NewStaticRegions(nil, []backend.AWSAccount{
		{ID: "123456789012", AllowedRegions: []string{"us-east-1"}},
	})
	verifier := func(service sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{
			Service: service, Regions: catalog,
			Auth: sigv4.Lookup(func(_ context.Context, key string) (sigv4.Credential, bool) {
				return routedCredential(t), key == "caller-key"
			}),
		})
	}
	return router.New(router.Config{
		Regions: catalog, Error: s3rest.WriteError,
		Forward: forward.Any(router.ForwardConfig{
			Verifier: verifier, Authorizer: actionAllowlist(allowed), Error: s3rest.WriteError,
		}),
	})
}

func routedCredential(t *testing.T) sigv4.Credential {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return sigv4.Credential{AccessKey: "caller-key", Secret: "caller-secret", Account: account, Principal: "principal"}
}

func TestS3HeaderPermissionsBeforeOrigin(t *testing.T) {
	for _, header := range []struct{ name, value, action string }{
		{"X-Amz-Acl", "public-read", "s3:PutObjectAcl"},
		{"X-Amz-Grant-Read", `id="reader"`, "s3:PutObjectAcl"},
		{"X-Amz-Grant-Read-Acp", `id="owner"`, "s3:PutObjectAcl"},
		{"X-Amz-Grant-Write-Acp", `id="owner"`, "s3:PutObjectAcl"},
		{"X-Amz-Grant-Full-Control", `id="owner"`, "s3:PutObjectAcl"},
		{"X-Amz-Tagging", "key=value", "s3:PutObjectTagging"},
		{"X-Amz-Tagging-Directive", "REPLACE", "s3:PutObjectTagging"},
		{"X-Amz-Object-Lock-Mode", "GOVERNANCE", "s3:PutObjectRetention"},
		{"X-Amz-Object-Lock-Retain-Until-Date", "2030-01-01T00:00:00Z", "s3:PutObjectRetention"},
		{"X-Amz-Object-Lock-Legal-Hold", "ON", "s3:PutObjectLegalHold"},
	} {
		for _, operation := range []string{"put", "copy", "multipart"} {
			t.Run(header.name+"/"+operation, func(t *testing.T) {
				f := setup(t)
				var calls atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get(header.name) != header.value {
						t.Error("authorized header changed")
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer origin.Close()
				if err := f.p.ServiceEndpoint(origin.URL); err != nil {
					t.Fatal(err)
				}
				base := []string{"s3:PutObject"}
				if operation == "copy" {
					base = append(base, "s3:GetObject")
				}
				for _, allow := range []bool{false, true} {
					actions := slices.Clone(base)
					if allow {
						actions = append(actions, header.action)
					}
					h := routedProxy(t, f.p, actions...)
					for range 2 {
						method, target := "PUT", "http://s3.vws.test/bucket/key"
						if operation == "multipart" {
							method, target = "POST", target+"?uploads"
						}
						r := httptest.NewRequestWithContext(t.Context(), method, target, nil)
						r.Header.Set(header.name, header.value)
						signed := []string{strings.ToLower(header.name)}
						if operation == "copy" {
							r.Header.Set("X-Amz-Copy-Source", "/source/key")
							signed = append(signed, "x-amz-copy-source")
						}
						err := sigv4.SignHeaders(r, routedCredential(t), sigv4.ServiceS3, "us-east-1", time.Now(), signed...)
						if err != nil {
							t.Fatal(err)
						}
						w := httptest.NewRecorder()
						h.ServeHTTP(w, r)
						if !allow && (w.Code != 403 || calls.Load() != 0 || f.stsCalls != 0) ||
							allow && w.Code != 200 {
							t.Fatalf("allow=%t status=%d STS=%d origin=%d: %s", allow, w.Code, f.stsCalls, calls.Load(), w.Body)
						}
					}
				}
				if calls.Load() != 2 || f.stsCalls != 1 {
					t.Fatalf("replay: STS=%d origin=%d", f.stsCalls, calls.Load())
				}
			})
		}
	}
}

func TestRoutedS3AddressAndEmptySignature(t *testing.T) {
	for _, tc := range []struct{ method, path, action string }{
		{"GET", "/key", "s3:GetObject"},
		{"GET", "/a%2Fb%20key", "s3:GetObject"},
		{"GET", "/", "s3:ListBucket"},
		{"HEAD", "/a%2Fb%20key", "s3:GetObject"},
		{"POST", "/a%2Fb%20key?uploads", "s3:PutObject"},
		{"PUT", "/a%2Fb%20key", "s3:PutObject"},
	} {
		for _, virtual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/virtual=%t", tc.method, virtual), func(t *testing.T) {
				f := setup(t)
				var calls atomic.Int32
				bucket, path := "photos.backup", tc.path
				if !virtual {
					path = "/" + bucket + strings.TrimSuffix(path, "/")
				}
				var originHost string
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					cred := routedCredential(t)
					cred.AccessKey, cred.Secret, cred.SessionToken = "session-canary-key", "session-canary-secret", "session-token"
					v := sigv4.NewVerifier(sigv4.Verifier{
						Service: sigv4.ServiceS3,
						Regions: backend.NewStaticRegions(nil, []backend.AWSAccount{
							{ID: "123456789012", AllowedRegions: []string{"us-east-1"}},
						}),
						Auth: sigv4.Lookup(func(_ context.Context, key string) (sigv4.Credential, bool) {
							return cred, key == cred.AccessKey
						}),
					})
					wantHost := originHost
					if virtual {
						wantHost = bucket + "." + wantHost
					}
					if r.Host != wantHost || r.URL.RequestURI() != path || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
						t.Errorf("wrong address or framing: host=%s URI=%s length=%d encoding=%v",
							r.Host, r.URL.RequestURI(), r.ContentLength, r.TransferEncoding)
					}
					if r.Header.Get("X-Vws-Original-Host") != "" || r.Header.Get("X-Vws-S3-Bucket") != "" {
						t.Error("untrusted routing metadata reached origin")
					}
					if _, err := v.Verify(r); err != nil {
						t.Errorf("origin signature: %v", err)
						w.WriteHeader(http.StatusForbidden)
						return
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer origin.Close()
				originHost = strings.TrimPrefix(origin.URL, "http://")
				if err := f.p.ServiceEndpoint(origin.URL); err != nil {
					t.Fatal(err)
				}
				tr := f.p.transport.(*http.Transport)
				dial := tr.DialContext
				tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != originHost && address != bucket+"."+originHost && address != f.stsHost {
						t.Errorf("unexpected destination %q", address)
					}
					if address == bucket+"."+originHost {
						address = originHost
					}
					return dial(ctx, network, address)
				}
				h := routedProxy(t, f.p, tc.action)
				for range 2 {
					host := "s3.vws.test"
					if virtual {
						host = bucket + "." + host
					}
					r := httptest.NewRequestWithContext(t.Context(), tc.method, "http://"+host+":443"+path, nil)
					r.Header.Set("X-Vws-Original-Host", "evil.s3.attacker.test")
					r.Header.Set("X-Vws-S3-Bucket", "evil")
					if err := sigv4.Sign(r, routedCredential(t), sigv4.ServiceS3, "us-east-1", time.Now()); err != nil {
						t.Fatal(err)
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 200 {
						t.Fatalf("status=%d body=%s", w.Code, w.Body)
					}
					clear(f.p.cache)
				}
				if calls.Load() != 2 || f.stsCalls != 2 {
					t.Fatalf("restart replay: STS=%d origin=%d", f.stsCalls, calls.Load())
				}
			})
		}
	}
}
