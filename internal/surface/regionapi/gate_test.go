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
	err   error
	calls int
}

func (g *mutationGate) Admit(context.Context) error {
	g.calls++
	return g.err
}

func TestMutationRegistrationDerivesQuorumGate(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"quorum", nil, http.StatusOK},
		{"no quorum", &resource.Error{Code: resource.CodeUnavailable}, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			gate := &mutationGate{err: test.err}
			calls := 0
			register(mux, Config{Gate: gate}, "Compute", "Mutation", func(
				_ context.Context, _ backend.Mutation, _ struct{},
			) (struct{}, error) {
				calls++
				return struct{}{}, nil
			})
			register(mux, Config{Gate: gate}, "Compute", "Read", func(
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
