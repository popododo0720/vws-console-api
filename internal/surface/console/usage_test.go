package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const usagePath = "/api/v1/usage?from=2026-10-01&to=2026-11-01"

type allocationReader func(context.Context, backend.Scope, struct{}) (resource.Allocation, error)

func (f allocationReader) GetAllocation(ctx context.Context, s backend.Scope, q struct{}) (resource.Allocation, error) {
	return f(ctx, s, q)
}

func TestUsageWindowAndAuthorization(t *testing.T) {
	e, _ := adminFixture(t)
	calls := 0
	e.h.(*handler).svc = cloud.New(cloud.Config{Backends: backend.Set{Usage: allocationReader(func(
		ctx context.Context, _ backend.Scope, _ struct{},
	) (resource.Allocation, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("unbounded allocation call")
		}
		return resource.Allocation{VCPU: 2}, nil
	})}})
	bearer := map[string]string{"Authorization": "Bearer tok"}
	for _, query := range []string{
		"", "from=2026-10-01", "from=bad&to=2026-11-01",
		"from=2026-02-30&to=2026-11-01", "from=2026-1-01&to=2026-11-01",
		"from=2026-11-01&to=2026-11-01", "from=2026-11-02&to=2026-11-01",
		"from=2020-01-01&to=2026-11-01", "from=2026-10-01&to=2026-11-01&project=other",
		"from=2026-10-01&from=2026-10-01&to=2026-11-01", "from=%zz&to=2026-11-01",
	} {
		rec := e.do(t, http.MethodGet, "/api/v1/usage?"+query, "", bearer)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d %s", query, rec.Code, rec.Body)
		}
	}
	user, _ := e.login(t)
	if rec := e.do(t, http.MethodGet, usagePath, "", nil, user); rec.Code != http.StatusForbidden {
		t.Fatalf("usage without grant: %d %s", rec.Code, rec.Body)
	}
	if calls != 0 {
		t.Fatal("invalid or denied request reached allocation")
	}
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "usage",
		`{"Statement":[{"Effect":"Allow","Action":"vws:GetUsage","Resource":"*"}]}`,
		backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, http.MethodGet, usagePath, "", nil, user); rec.Code != http.StatusOK || calls != 1 {
		t.Fatalf("usage with grant: %d %s, calls %d", rec.Code, rec.Body, calls)
	}
}

func TestUsageFailureMetadataAndRegistry(t *testing.T) {
	e, _ := adminFixture(t)
	h := e.h.(*handler)
	h.svc = cloud.New(cloud.Config{Backends: backend.Set{Usage: allocationReader(func(
		context.Context, backend.Scope, struct{},
	) (resource.Allocation, error) {
		return resource.Allocation{}, errors.New("https://private:secret@10.9.9.9:8006")
	})}})
	bearer := map[string]string{"Authorization": "Bearer tok"}
	rec := e.do(t, http.MethodGet, usagePath, "", bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"error":"Unavailable"`) ||
		strings.Contains(rec.Body.String(), `"allocation"`) || strings.Contains(rec.Body.String(), "10.9.9.9") ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("failed region looks successful or exposes transport: %d %s", rec.Code, rec.Body)
	}
	h.registry = store.New(failedProjectStore{
		Backend: store.NewMemory(), err: errors.New("https://secret@10.9.9.9:2379"),
	})
	rec = e.do(t, http.MethodGet, usagePath, "", bearer)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "project registry read failed") ||
		strings.Contains(rec.Body.String(), "10.9.9.9") {
		t.Fatalf("registry failure: %d %s", rec.Code, rec.Body)
	}
	h.registry = nil
	if rec := e.do(t, http.MethodGet, usagePath, "", bearer); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing registry: %d %s", rec.Code, rec.Body)
	}
}
