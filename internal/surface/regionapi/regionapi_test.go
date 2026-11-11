package regionapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func testScope(t *testing.T) backend.Scope {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return backend.Scope{Account: account}
}

func config(set backend.Set) Config {
	return Config{
		Backend: set, Capabilities: backend.AllSupported{Kind: resource.RegionKindProxmox},
		Region: "pve-test", Version: Version{ReleaseLine: "1.0", ClusterName: "test-cluster"},
	}
}

func certificates(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		b, err := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: k}
	}
	return leaf(2, x509.ExtKeyUsageServerAuth), leaf(3, x509.ExtKeyUsageClientAuth), pool
}

func loopback(t *testing.T, cfg Config) (*Client, *httptest.Server) {
	t.Helper()
	serverCert, clientCert, pool := certificates(t)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = NewServer("", h, serverCert, pool).http.TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool,
		Certificates: []tls.Certificate{clientCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, srv
}

func TestEveryReadRoundTrips(t *testing.T) {
	ctx := context.Background()
	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	ops := seedReads(t, set, scope)
	bucket, err := resource.Parse[resource.BucketName]("test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	key, err := resource.Parse[resource.ObjectKey]("hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.CreateBucket(ctx, scope, bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.PutObject(ctx, scope, resource.PutObjectRequest{
		Bucket: bucket, Key: key,
		Size: 5,
	}, strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	c, _ := loopback(t, config(set))
	remote, err := regionclient.New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []struct {
		name   string
		typ    reflect.Type
		value  any
		remote any
	}{
		{"Compute", reflect.TypeFor[backend.Compute](), set.Compute, remote.Compute},
		{"Storage", reflect.TypeFor[backend.Storage](), set.Storage, remote.Storage},
		{"Network", reflect.TypeFor[backend.Network](), set.Network, remote.Network},
	} {
		for i := 0; i < service.typ.NumMethod(); i++ {
			method := service.typ.Method(i)
			if !strings.HasPrefix(method.Name, "Describe") && !strings.HasPrefix(method.Name, "Get") &&
				!strings.HasPrefix(method.Name, "List") {
				continue
			}
			t.Run(service.name+"/"+method.Name, func(t *testing.T) {
				q := reflect.New(method.Type.In(2)).Elem()
				if q.Kind() == reflect.Struct {
					if page := q.FieldByName("Page"); page.IsValid() {
						page.Set(reflect.ValueOf(resource.PageRequest{Size: 100}))
					}
				}
				switch method.Name {
				case "GetBucket":
					q.Set(reflect.ValueOf(bucket))
				case "GetObject":
					q.Set(reflect.ValueOf(resource.GetObjectRequest{Bucket: bucket, Key: key}))
				case "ListObjects":
					q.Set(reflect.ValueOf(resource.ObjectQuery{Bucket: bucket}))
				case "GetOperation":
					q.Set(reflect.ValueOf(ops[service.name]))
				}
				out := reflect.ValueOf(service.value).MethodByName(method.Name).Call([]reflect.Value{
					reflect.ValueOf(ctx), reflect.ValueOf(scope), q,
				})
				var directErr error
				if !out[len(out)-1].IsNil() {
					directErr = out[len(out)-1].Interface().(error)
				}
				dst := reflect.New(method.Type.Out(0)).Interface()
				want := out[0].Interface()
				if method.Name == "GetObject" && directErr == nil {
					body, ok := out[1].Interface().(io.ReadCloser)
					if !ok {
						t.Fatal("GetObject returned no stream")
					}
					data, err := io.ReadAll(body)
					if err != nil {
						t.Fatal(err)
					}
					if err := body.Close(); err != nil {
						t.Fatal(err)
					}
					want = ObjectResult{Object: out[0].Interface().(resource.Object), Body: data}
					dst = &ObjectResult{}
				}
				wire := reflect.ValueOf(service.remote).MethodByName(method.Name).Call([]reflect.Value{
					reflect.ValueOf(ctx), reflect.ValueOf(scope), q,
				})
				var err error
				if !wire[len(wire)-1].IsNil() {
					err = wire[len(wire)-1].Interface().(error)
				}
				if method.Name == "GetObject" && err == nil {
					body := wire[1].Interface().(io.ReadCloser)
					data, readErr := io.ReadAll(body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					if err := body.Close(); err != nil {
						t.Fatal(err)
					}
					dst = &ObjectResult{Object: wire[0].Interface().(resource.Object), Body: data}
				} else {
					reflect.ValueOf(dst).Elem().Set(wire[0])
				}
				if resource.CodeOf(err) != resource.CodeOf(directErr) {
					t.Fatalf("wire %v, direct %v", err, directErr)
				}
				if directErr != nil {
					return
				}
				if got := reflect.ValueOf(dst).Elem().Interface(); !reflect.DeepEqual(got, want) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			})
		}
	}
	caps, err := c.Capabilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantCaps, err := config(set).Capabilities.RegionCapabilities(ctx, "pve-test")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(caps, wantCaps) {
		t.Fatalf("capabilities changed: %+v", caps)
	}
	v, err := c.Version(ctx)
	if err != nil || v != config(set).Version {
		t.Fatalf("version %+v: %v", v, err)
	}
}

type errorCompute struct {
	backend.Compute
	err error
}

func (c errorCompute) DescribeInstances(
	context.Context, backend.Scope, resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return resource.Page[resource.Instance]{}, c.err
}

func TestErrorCodesRoundTrip(t *testing.T) {
	for _, code := range append(resource.Codes(), resource.CodeUnspecified) {
		t.Run(code.String(), func(t *testing.T) {
			set := fake.New(fake.Options{}).Set()
			set.Compute = errorCompute{
				Compute: set.Compute,
				err: (&resource.Error{
					Code: code, Message: "domain message", Kind: resource.KindInstance,
					ID: "i-0123456789abcdef0", Field: "instanceId",
				}).WithCause(fmt.Errorf("private secret")),
			}
			c, _ := loopback(t, config(set))
			remote, err := regionclient.New(c)
			if err != nil {
				t.Fatal(err)
			}
			_, err = remote.Compute.DescribeInstances(context.Background(), testScope(t), resource.InstanceQuery{})
			if err == nil || resource.CodeOf(err) != code || resource.AsError(err).Message != "domain message" ||
				strings.Contains(err.Error(), "private secret") {
				t.Fatalf("error changed: %v", err)
			}
			if e := resource.AsError(err); e.Kind != resource.KindInstance || e.ID != "i-0123456789abcdef0" ||
				e.Field != "instanceId" {
				t.Fatalf("error context changed: %+v", e)
			}
		})
	}
}

func TestMTLSRejectsUntrustedClients(t *testing.T) {
	_, srv := loopback(t, config(fake.New(fake.Options{}).Set()))
	_, wrongCert, _ := certificates(t)
	for _, certs := range [][]tls.Certificate{nil, {wrongCert}} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, Certificates: certs,
		}}
		httpClient := &http.Client{Transport: tr, Timeout: time.Second}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/v1/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := httpClient.Do(req)
		if err == nil {
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			t.Fatal("untrusted client reached HTTP")
		}
		if !strings.Contains(err.Error(), "tls") {
			t.Fatalf("expected TLS rejection: %v", err)
		}
		tr.CloseIdleConnections()
	}
}

func TestInputAndRouteBounds(t *testing.T) {
	h, err := New(config(fake.New(fake.Options{}).Set()))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		"null", `{}`, `{"scope":null,"req":{}}`,
		`{"scope":{"Account":"123456789012"},"req":{},"unknown":1}`,
		`{"scope":{"Account":"123456789012"},"req":{}} {}`, strings.Repeat(" ", maxRequestBytes+1),
	} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/internal/v1/Compute/DescribeInstances", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body accepted: %d", w.Code)
		}
	}
	for _, path := range []string{
		"Compute/RunInstances", "Storage/CreateBucket", "Network/DeleteSubnet", "Compute/Unknown",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(),
			http.MethodPost, "/internal/v1/"+path, strings.NewReader(`{}`)))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s routed: %d", path, w.Code)
		}
	}
	srv := NewServer(":0", h, tls.Certificate{}, x509.NewCertPool())
	if srv.http.ReadHeaderTimeout <= 0 || srv.http.ReadTimeout <= 0 ||
		srv.http.WriteTimeout <= 0 || srv.http.IdleTimeout <= 0 {
		t.Fatal("unbounded listener")
	}
	if srv.http.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("client certificate not verified")
	}
}
