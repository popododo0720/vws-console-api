package regionapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type objectStorage struct {
	backend.Storage
	body io.ReadCloser
}

func (s objectStorage) GetObject(context.Context, backend.Scope, resource.GetObjectRequest) (
	resource.Object, io.ReadCloser, error,
) {
	return resource.Object{}, s.body, nil
}

type trackedBody struct {
	io.Reader
	closed   bool
	closeErr error
}

func (b *trackedBody) Close() error { b.closed = true; return b.closeErr }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestObjectFailureClosesTheStream(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reader   io.Reader
		closeErr error
		code     resource.Code
	}{
		{"read", brokenReader{}, nil, resource.CodeInternal},
		{"close", strings.NewReader("data"), errors.New("close failed"), resource.CodeInternal},
		{"size", strings.NewReader(strings.Repeat("x", resource.MaxObjectBytes+1)), nil, resource.CodePayloadTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: tc.reader, closeErr: tc.closeErr}
			set := fake.New(fake.Options{}).Set()
			set.Storage = objectStorage{Storage: set.Storage, body: body}
			h := New(config(set))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"/internal/v1/Storage/GetObject", strings.NewReader(`{"scope":{"Account":"123456789012"},"req":{}}`)))
			if !body.closed || !strings.Contains(w.Body.String(), tc.code.String()) {
				t.Fatalf("closed=%t response=%s", body.closed, w.Body.String())
			}
		})
	}
}

func TestCanceledAndRepeatedReads(t *testing.T) {
	c, _ := loopback(t, config(fake.New(fake.Options{}).Set()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Version(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	for range 2 {
		if _, err := c.Version(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, origin := range []string{"http://region", "https://region/path", "https://user@region", "https://region?q=1"} {
		if _, err := NewClient(origin, nil); err == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
}
