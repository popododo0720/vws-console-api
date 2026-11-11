package regionapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationBodyBound(t *testing.T) {
	called := false
	h := WithRegistration(func(context.Context, json.RawMessage) error {
		called = true
		return nil
	}, http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/internal/v1/registration",
		strings.NewReader(strings.Repeat("x", (64<<10)+1))))
	if called || rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatal("oversized registration reached writer")
	}
}
