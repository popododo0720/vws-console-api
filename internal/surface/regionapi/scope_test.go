package regionapi

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestScopeCheckPrecedesReadsMutationsAndConsole(t *testing.T) {
	cfg := config(fake.New(fake.Options{}).Set())
	checks := 0
	cfg.CheckScope = func(scope backend.Scope) error {
		checks++
		return resource.Denied("unmanaged pool")
	}
	client, _ := loopback(t, cfg)
	scope := testScope(t)
	scope.Pool = "foreign"
	for _, call := range []struct {
		service, method string
		input           any
	}{
		{"Compute", "DescribeInstances", scope},
		{"Compute", "CreateVolume", backend.Mutation{Scope: scope}},
		{"Storage", "CreateBucket", scope},
		{"Console", "OpenConsole", scope},
	} {
		var output any
		req := any(struct{}{})
		if call.service == "Storage" {
			req = "test-bucket"
		}
		err := client.Call(context.Background(), call.service, call.method, call.input, req, &output)
		if resource.CodeOf(err) != resource.CodePermissionDenied {
			t.Fatalf("%s.%s bypassed scope check: %v", call.service, call.method, err)
		}
	}
	if checks != 4 {
		t.Fatalf("scope checks: %d", checks)
	}
}
