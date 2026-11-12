package pvefake_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func TestPoolWritesAreViolations(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		for _, path := range []string{"/api2/json/pools", "/api2/json/pools/vws-a"} {
			t.Run(method+path, func(t *testing.T) {
				f, err := pvefake.New(scenario(t))
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				f.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, path, nil))
				want := []string{method + " " + path}
				if w.Code != http.StatusNotImplemented || !reflect.DeepEqual(f.PoolWriteViolations(), want) {
					t.Fatalf("status=%d violations=%v", w.Code, f.PoolWriteViolations())
				}
				copyOf := f.PoolWriteViolations()
				copyOf[0] = "changed"
				if !reflect.DeepEqual(f.PoolWriteViolations(), want) {
					t.Fatal("violation accessor shares mutable state")
				}
			})
		}
	}
}
