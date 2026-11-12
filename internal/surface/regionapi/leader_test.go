package regionapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type mutationGate struct {
	peer  string
	err   error
	calls int
}

func (g *mutationGate) Admit(context.Context) (string, error) {
	g.calls++
	return g.peer, g.err
}

func TestMutationRegistrationDerivesLeaderGate(t *testing.T) {
	for _, test := range []struct {
		name, peer string
		err        error
		status     int
	}{
		{"leader", "", nil, http.StatusOK},
		{"follower", "pve2", nil, http.StatusServiceUnavailable},
		{"unknown", "", &resource.Error{Code: resource.CodeUnavailable}, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			gate := &mutationGate{peer: test.peer, err: test.err}
			calls := 0
			register(mux, gate, "Compute", "Mutation", func(
				_ context.Context, _ backend.Mutation, _ struct{},
			) (struct{}, error) {
				calls++
				return struct{}{}, nil
			})
			register(mux, gate, "Compute", "Read", func(
				_ context.Context, _ backend.Scope, _ struct{},
			) (struct{}, error) {
				return struct{}{}, nil
			})
			for _, method := range []string{"Mutation", "Read"} {
				field := "scope"
				if method == "Mutation" {
					field = "mutation"
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/internal/v1/Compute/"+method,
					strings.NewReader(`{"`+field+`":{"account":"123456789012"},"req":{}}`))
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				want := test.status
				if method == "Read" {
					want = http.StatusOK
				}
				if rec.Code != want {
					t.Fatalf("%s: status=%d body=%s", method, rec.Code, rec.Body.String())
				}
			}
			if gate.calls != 1 || (calls == 1) != (test.status == http.StatusOK) {
				t.Fatalf("admit calls=%d backend mutation calls=%d", gate.calls, calls)
			}
		})
	}
}
