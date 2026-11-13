package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func serviceRequest(method, target, service, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	for k, v := range map[string]string{
		"X-Vws-Account": "123456789012", "X-Vws-Principal": "principal",
		"X-Vws-Target-Region": "us-east-1", "X-Vws-Target-Service": service,
		"Authorization": "caller-signature", "X-Amz-Date": "20200101T000000Z",
		"X-Amz-Security-Token": "caller-token", "X-Amz-User-Agent": "caller-agent",
		"Connection": "X-Amz-Hop, Range", "X-Amz-Hop": "drop", "Range": "bytes=0-3",
		"Expect": "100-continue", "Proxy-Secret": "drop", "Cookie": "drop",
	} {
		r.Header.Set(k, v)
	}
	return r
}

func chunked(body string, more ...string) string {
	sig := strings.Repeat("0", 64)
	var wire strings.Builder
	for _, part := range append([]string{body}, more...) {
		fmt.Fprintf(&wire, "%x;chunk-signature=%s\r\n%s\r\n", len(part), sig, part)
	}
	fmt.Fprintf(&wire, "0;chunk-signature=%s\r\n\r\n", sig)
	return wire.String()
}

func TestServiceResignAndResponsePassThrough(t *testing.T) {
	for _, tc := range []struct {
		name, service, method, target, body, contentType, encoding string
		stream, hash, virtual                                      bool
	}{
		{
			name: "EC2 Query", service: "ec2", method: "POST", target: "/",
			body: "Action=DescribeRegions&Version=2016-11-15", contentType: "application/x-www-form-urlencoded",
		},
		{
			name: "Query", service: "rds", method: "POST", target: "/",
			body: "Action=DescribeDBInstances", contentType: "application/x-www-form-urlencoded",
		},
		{
			name: "JSON", service: "dynamodb", method: "POST", target: "/", body: `{"TableName":"t"}`,
			contentType: "application/x-amz-json-1.0",
		},
		{name: "JSON with hash", service: "dynamodb", method: "POST", target: "/", body: `{}`, hash: true},
		{
			name: "S3 path", service: "s3", method: "PUT", target: "/bucket/a%2Fb%20key?versionId=v1&partNumber=2",
			body: "bytes\x00\xff",
		},
		{name: "S3 virtual", service: "s3", method: "PUT", target: "/a%2Fb%20key", body: "object", virtual: true},
		{
			name: "chunked", service: "s3", method: "PUT", target: "/bucket/key", body: "decoded\x00\xff",
			stream: true, encoding: "aws-chunked",
		},
		{
			name: "chunked and gzip", service: "s3", method: "PUT", target: "/bucket/key", body: "compressed bytes",
			stream: true, encoding: "gzip, aws-chunked",
		},
		{name: "empty GET", service: "s3", method: "GET", target: "/bucket/key"},
		{
			name: "multi chunked", service: "s3", method: "PUT", target: "/bucket/key", body: "firstsecond",
			stream: true, encoding: "aws-chunked",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			account, err := resource.Parse[resource.AccountID]("123456789012")
			if err != nil {
				t.Fatal(err)
			}
			session := sigv4.Credential{
				AccessKey: "session-canary-key", Secret: "session-canary-secret",
				SessionToken: "session-token", Account: account,
			}
			verified := make(chan *http.Request, 1)
			response := []byte("arn:aws:s3:::bucket/key\x00\xff")
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := sigv4.NewVerifier(sigv4.Verifier{
					Service: sigv4.Service(tc.service),
					Regions: backend.NewStaticRegions(nil, []backend.AWSAccount{
						{ID: "123456789012", AllowedRegions: []string{"us-east-1"}},
					}),
					Auth: sigv4.Lookup(func(_ context.Context, key string) (sigv4.Credential, bool) {
						return session, key == session.AccessKey
					}),
				})
				if _, err := v.Verify(r); err != nil {
					t.Errorf("origin signature verification: %v", err)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Errorf("origin body = %q, error = %v", body, err)
				}
				verified <- r.Clone(r.Context())
				w.Header()["X-Origin"] = []string{"first", "second"}
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Connection", "X-Hop")
				w.Header().Set("X-Hop", "drop")
				w.Header().Set("Proxy-Secret", "drop")
				w.Header().Set("Expect", "drop")
				w.Header().Set("Content-Length", fmt.Sprint(len(response)))
				w.WriteHeader(http.StatusPartialContent)
				if _, err := w.Write(response); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(origin.Close)
			f.p.origin = origin.URL
			if err := f.p.ServiceEndpoint(origin.URL); err != nil {
				t.Fatal(err)
			}
			host := strings.TrimPrefix(origin.URL, "http://")
			if tc.virtual {
				tr := f.p.transport.(*http.Transport)
				dial := tr.DialContext
				tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address == "photos.backup."+host {
						address = host
					}
					return dial(ctx, network, address)
				}
			}
			wire := tc.body
			if tc.stream {
				wire = chunked(tc.body)
				if tc.name == "multi chunked" {
					wire = chunked(tc.body[:3], tc.body[3:])
				}
			}
			r := serviceRequest(tc.method, tc.target, tc.service, wire)
			if tc.virtual {
				r.Host = "photos.backup.s3.vws.test:443"
			}
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.hash {
				r.Header.Set("X-Amz-Content-Sha256", "stale-hash")
			}
			if tc.service == "dynamodb" {
				r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
			}
			if tc.stream {
				r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
				r.Header.Set("Content-Encoding", tc.encoding)
				r.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(len(tc.body)))
			}
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, r)
			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), response) {
				t.Fatalf("response changed: status=%d body=%q", w.Code, w.Body.Bytes())
			}
			if strings.Join(w.Header().Values("X-Origin"), ",") != "first,second" ||
				w.Header().Get("Content-Encoding") != "gzip" {
				t.Fatal("end-to-end response headers changed")
			}
			for _, name := range []string{"Connection", "X-Hop", "Proxy-Secret", "Expect"} {
				if w.Header().Get(name) != "" {
					t.Errorf("response retained %s", name)
				}
			}
			got := <-verified
			wantHost := host
			if tc.virtual {
				wantHost = "photos.backup." + host
			}
			if got.Host != wantHost || got.URL.RequestURI() != tc.target || got.Method != tc.method ||
				got.ContentLength != int64(len(tc.body)) || got.Header.Get("X-Amz-Security-Token") != "session-token" {
				t.Errorf("origin request changed: host=%s URI=%s length=%d", got.Host, got.URL.RequestURI(), got.ContentLength)
			}
			for _, name := range []string{
				"X-Amz-Hop", "Range", "Expect", "Proxy-Secret", "Cookie", "X-Vws-Account",
				"X-Amz-Decoded-Content-Length",
			} {
				if got.Header.Get(name) != "" {
					t.Errorf("request retained %s", name)
				}
			}
			auth := got.Header.Get("Authorization")
			for _, name := range []string{"content-length", "x-amz-user-agent"} {
				if !strings.Contains(auth, name) {
					t.Errorf("unsigned header %s", name)
				}
			}
			if got.Header.Get("X-Amz-Target") != r.Header.Get("X-Amz-Target") ||
				got.Header.Get("X-Amz-User-Agent") != "caller-agent" {
				t.Fatal("service headers changed")
			}
			wantHash := tc.service == "s3" || tc.hash
			if (got.Header.Get("X-Amz-Content-Sha256") != "") != wantHash {
				t.Fatal("payload hash presence changed")
			}
			if tc.stream && got.Header.Get("Content-Encoding") != strings.TrimSuffix(tc.encoding, "aws-chunked") &&
				got.Header.Get("Content-Encoding") != "gzip" {
				t.Fatal("streaming encoding was not removed")
			}
		})
	}
}

func TestServiceRefusalsMakeNoOutboundCall(t *testing.T) {
	for name, edit := range map[string]func(*http.Request){
		"presigned":         func(r *http.Request) { r.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256" },
		"presigned encoded": func(r *http.Request) { r.URL.RawQuery = "%58-Amz-Signature=abc" },
		"unsigned":          func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") },
		"region set":        func(r *http.Request) { r.Header.Set("X-Amz-Region-Set", "*") },
		"empty region set":  func(r *http.Request) { r.Header["X-Amz-Region-Set"] = []string{""} },
		"SigV4a":            func(r *http.Request) { r.Header.Set("Authorization", "AWS4-ECDSA-P256-SHA256 invalid") },
	} {
		for _, service := range []string{"ec2", "s3", "dynamodb"} {
			t.Run(name+"/"+service, func(t *testing.T) {
				f := setup(t)
				var outbound atomic.Int64
				f.p.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
					outbound.Add(1)
					return nil, errors.New("credential-canary")
				})
				if err := f.p.ServiceEndpoint("http://127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				r := serviceRequest("POST", "/", service, "Action=DescribeRegions")
				edit(r)
				w := httptest.NewRecorder()
				f.p.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden || outbound.Load() != 0 ||
					!strings.Contains(w.Body.String(), "<Code>UnauthorizedOperation</Code>") {
					t.Fatalf("status=%d outbound=%d body=%s", w.Code, outbound.Load(), w.Body)
				}
			})
		}
	}
}

func TestMalformedChunkedBodiesMakeNoOutboundCall(t *testing.T) {
	for name, wire := range map[string]string{
		"bad size":         strings.Replace(chunked("data"), "4;", "z;", 1),
		"overflow":         strings.Replace(chunked("data"), "4;", "fffffffffffffffff;", 1),
		"negative":         strings.Replace(chunked("data"), "4;", "-4;", 1),
		"truncated":        chunked("data")[:90],
		"no terminator":    chunked("data")[:len(chunked("data"))-2],
		"extra bytes":      chunked("data") + "extra",
		"signature":        strings.Replace(chunked("data"), strings.Repeat("0", 64), "bad", 1),
		"over max":         chunked(strings.Repeat("x", resource.MaxObjectBytes+1)),
		"claimed over max": strings.Replace(chunked("data"), "4;", "400001;", 1),
		"decoded mismatch": chunked("data"),
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			var outbound atomic.Int64
			f.p.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				outbound.Add(1)
				return nil, errors.New("credential-canary")
			})
			if err := f.p.ServiceEndpoint("http://127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			r := serviceRequest("PUT", "/bucket/key", "s3", wire)
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
			if name == "decoded mismatch" {
				r.Header.Set("X-Amz-Decoded-Content-Length", "99")
			}
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || outbound.Load() != 0 ||
				w.Body.String() != "<Response><Errors><Error><Code>InvalidParameterValue</Code></Error></Errors></Response>" {
				t.Fatalf("status=%d outbound=%d body=%s", w.Code, outbound.Load(), w.Body)
			}
		})
	}
}

func TestServiceEndpointBoundary(t *testing.T) {
	f := setup(t)
	for _, raw := range []string{
		"", "http://{service}.example.test", "https://user@example.test",
		"https://example.test/path", "https://example.test?q=1", "https://example.test#fragment",
	} {
		if err := f.p.ServiceEndpoint(raw); err == nil {
			t.Errorf("accepted endpoint %q", raw)
		}
	}
	if err := f.p.ServiceEndpoint("https://{service}.{region}.example.test"); err != nil {
		t.Fatal(err)
	}
}
