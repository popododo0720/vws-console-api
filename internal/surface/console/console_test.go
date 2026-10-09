package console

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestEveryActionHasARoute(t *testing.T) {
	h := &handler{}
	for _, action := range resource.Actions() {
		method, pattern, handle := h.mutation(action)
		if method == "" || pattern == "" || handle == nil {
			t.Fatalf("%s has no console route", action)
		}
		if pattern == "/api/v1/unsupported" {
			t.Fatalf("%s fell through to the unsupported route", action)
		}
	}
}

func TestMissingBearerIsUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/instances", nil)
	rec := httptest.NewRecorder()
	New(Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}
