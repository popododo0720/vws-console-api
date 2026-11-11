package regionapi

import (
	"context"
	"reflect"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type failedCompute struct{ backend.Compute }

func (c failedCompute) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (
	resource.Operation, error,
) {
	op, err := c.Compute.GetOperation(ctx, s, id)
	if err == nil {
		op.State = resource.OperationFailed
		op.Error = resource.NotFound(resource.KindInstance, "i-0123456789abcdef0")
	}
	return op, err
}

func TestFailedOperationRoundTrips(t *testing.T) {
	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	ops := seedReads(t, set, scope)
	set.Compute = failedCompute{set.Compute}
	want, err := set.Compute.GetOperation(t.Context(), scope, ops["Compute"])
	if err != nil {
		t.Fatal(err)
	}
	c, _ := loopback(t, config(set))
	var got resource.Operation
	if err := c.Call(t.Context(), "Compute", "GetOperation", scope, ops["Compute"], &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
