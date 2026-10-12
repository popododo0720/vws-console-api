package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestEveryCodeHasAConsoleStatus pins the console status for each model
// code. The body code is the model code name.
func TestEveryCodeHasAConsoleStatus(t *testing.T) {
	want := map[resource.Code]int{
		resource.CodeInvalidArgument:     400,
		resource.CodeNotFound:            404,
		resource.CodeAlreadyExists:       409,
		resource.CodeConflict:            409,
		resource.CodeIdempotencyMismatch: 409,
		resource.CodeUnauthenticated:     401,
		resource.CodePermissionDenied:    403,
		resource.CodeResourceExhausted:   429,
		resource.CodePayloadTooLarge:     413,
		resource.CodeUnavailable:         503,
		resource.CodeUnimplemented:       501,
		resource.CodeInternal:            500,
	}
	if len(want) != len(resource.Codes()) {
		t.Errorf("%d rows for %d codes", len(want), len(resource.Codes()))
	}
	for _, c := range resource.Codes() {
		rec := httptest.NewRecorder()
		writeErr(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), &resource.Error{Code: c, Message: "m"})
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != want[c] || body.Error.Code != c.String() {
			t.Errorf("%v = %d %q, want %d %q", c, rec.Code, body.Error.Code, want[c], c.String())
		}
	}
}
