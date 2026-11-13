package regionapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
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

func TestRegistrationFailureSanitizesUpstream(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	shutdown, err := obs.Setup(t.Context(), obs.ForService("vws-region"), obs.WithOverride(func(c *obs.Config) {
		c.LogOutput = &logs
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	}()
	const secret = "upstream-token-and-kek-canary"
	const classified = "registration self-check failed: privileges"
	for _, failure := range []error{
		errors.New(secret),
		&resource.Error{Code: resource.CodeUnavailable, Message: classified + secret},
		(&resource.Error{
			Code: resource.CodeUnavailable, Message: classified, ID: secret, Field: secret,
		}).WithCause(errors.New(secret)),
	} {
		logs.Reset()
		h := WithRegistration(func(context.Context, json.RawMessage) error {
			return failure
		}, http.NotFoundHandler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPut,
			"/internal/v1/registration", strings.NewReader(secret)))
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("registration status = %d, headers = %v", rec.Code, rec.Header())
		}
		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == nil {
			t.Fatalf("registration error body = %s: %v", rec.Body, err)
		}
		if strings.Contains(logs.String()+rec.Body.String(), secret) {
			t.Fatalf("upstream secret escaped: %s %s", rec.Body, logs.String())
		}
		want := "registration failed"
		if resource.AsError(failure).Message == classified {
			want = classified
		}
		if body.Error.Message != want || !strings.Contains(logs.String(), want) {
			t.Fatalf("message = %q, logs = %s; want %q", body.Error.Message, logs.String(), want)
		}
	}
}
