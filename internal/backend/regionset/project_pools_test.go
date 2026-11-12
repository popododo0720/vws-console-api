package regionset_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type projectCatalog struct {
	backend.RegionCatalog
	lookup func(context.Context, resource.AccountID, string) (string, error)
}

func (c projectCatalog) ProjectPool(ctx context.Context, account resource.AccountID, region string) (string, error) {
	return c.lookup(ctx, account, region)
}

type poolTransport struct{ calls chan any }

func (p poolTransport) Call(_ context.Context, _, _ string, scope, _, _ any) error {
	p.calls <- scope
	return nil
}

func (p poolTransport) OpenConsole(
	_ context.Context, scope backend.Scope, _ resource.InstanceID, _ resource.ConsoleKind,
) (
	resource.ConsoleSession, error,
) {
	p.calls <- scope
	return resource.ConsoleSession{}, nil
}

func TestProjectPoolsBindReadsMutationsAndConsoles(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(chan any, 3)
	fail := false
	cat := projectCatalog{RegionCatalog: catalog(), lookup: func(
		ctx context.Context, project resource.AccountID, region string,
	) (string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || project != account {
			return "", errors.New("unbounded or foreign project lookup")
		}
		if fail {
			return "", errors.New("https://credentials@registry.invalid/secret")
		}
		return "pool-" + region, nil
	}}
	set, err := regionset.New(cat, func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
		return poolTransport{calls}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account, Region: "all", Principal: "principal", Pool: "forged"}
	if _, err := set.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		got := (<-calls).(backend.Scope)
		if got.Pool != "pool-"+got.Region || got.Account != account || got.Principal != scope.Principal {
			t.Fatalf("regional binding: %+v", got)
		}
	}
	scope.Region = "pve-a-1"
	mutation := backend.Mutation{Scope: scope, Key: "key", Fingerprint: "fp", MintedToken: true}
	if _, err := set.Compute.CreateVolume(t.Context(), mutation, resource.CreateVolumeRequest{}); err != nil {
		t.Fatal(err)
	}
	want := mutation
	want.Pool = "pool-pve-a-1"
	if got := (<-calls).(backend.Mutation); got != want {
		t.Fatalf("bound mutation: %+v, want %+v", got, want)
	}
	if _, err := set.Console.OpenConsole(t.Context(), scope, resource.InstanceID{}, resource.ConsoleVNC); err != nil {
		t.Fatal(err)
	}
	if got := (<-calls).(backend.Scope); got != want.Scope {
		t.Fatalf("console binding: %+v", got)
	}
	bucket, err := resource.Parse[resource.BucketName]("test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.CreateBucket(t.Context(), scope, bucket); err != nil {
		t.Fatal(err)
	}
	if got := (<-calls).(backend.Scope); got != want.Scope {
		t.Fatalf("synchronous storage binding: %+v", got)
	}
	fail = true
	_, err = set.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("mapping read failed open: %v", err)
	}
	_, err = set.Compute.CreateVolume(t.Context(), mutation, resource.CreateVolumeRequest{})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("mutation mapping read failed open: %v", err)
	}
	if len(calls) != 0 {
		t.Fatal("failed mapping reached region transport")
	}
}
