package regionapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestReadinessSafeReasonRoundTrip(t *testing.T) {
	const reason = `pool "vws-default": missing Pool.Audit`
	const secret = "upstream-secret-canary"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "not ready"},
		{errors.New(secret), "not ready"},
		{&resource.Error{Code: resource.CodeUnavailable, Message: secret}, "not ready"},
		{&resource.Error{Code: resource.CodeUnavailable, Message: reason + secret}, "not ready"},
		{
			(&resource.Error{Code: resource.CodeUnavailable, Message: reason, ID: secret, Field: secret}).
				WithCause(errors.New(secret)), reason,
		},
	} {
		t.Run(tc.want, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				WriteNotReady(w, tc.err)
			}))
			defer srv.Close()
			client := &Client{base: srv.URL, http: srv.Client()}
			_, err := client.Status(t.Context())
			regional := resource.AsError(err)
			if regional == nil || regional.Code != resource.CodeUnavailable || regional.Message != tc.want ||
				regional.ID != "" || regional.Field != "" || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe or missing region error: %#v", err)
			}
		})
	}
}
