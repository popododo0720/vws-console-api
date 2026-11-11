package regionset_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type transportFunc func(context.Context, string, string, backend.Scope, any, any) error

func (f transportFunc) Call(ctx context.Context, service, method string, s backend.Scope, q, dst any) error {
	return f(ctx, service, method, s, q, dst)
}

func catalog() *backend.StaticRegions {
	return backend.NewStaticRegions([]backend.ProxmoxRegion{
		{Name: "pve-c-1"}, {Name: "pve-a-1"}, {Name: "pve-b-1"},
	}, nil)
}

func newSet(t *testing.T, cat backend.RegionCatalog, f transportFunc) backend.Set {
	t.Helper()
	set, err := regionset.New(cat, func(_ context.Context, _ backend.ProxmoxRegion) (regionclient.Transport, error) {
		return f, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestEveryInventoryListRoutesAndPreservesQueries(t *testing.T) {
	for _, region := range []string{"pve-b-1", "all"} {
		t.Run(region, func(t *testing.T) {
			calls := make(chan backend.Scope, 3)
			account, _ := resource.Parse[resource.AccountID]("123456789012")
			set := newSet(t, catalog(), func(ctx context.Context, _, _ string, s backend.Scope, q, dst any) error {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					return errors.New("missing region deadline")
				}
				if reflect.ValueOf(q).FieldByName("Page").Interface() != (resource.PageRequest{Size: 7}) {
					return errors.New("query changed")
				}
				calls <- s
				items := reflect.ValueOf(dst).Elem().FieldByName("Items")
				items.Set(reflect.MakeSlice(items.Type(), 1, 1))
				return nil
			})
			for _, svc := range []any{set.Compute, set.Network, set.Storage} {
				v := reflect.ValueOf(svc)
				for i := 0; i < v.NumMethod(); i++ {
					name := v.Type().Method(i).Name
					if !strings.HasPrefix(name, "Describe") && name != "ListBuckets" {
						continue
					}
					t.Run(name, func(t *testing.T) {
						fn := v.Method(i)
						q := reflect.New(fn.Type().In(2)).Elem()
						q.FieldByName("Page").Set(reflect.ValueOf(resource.PageRequest{Size: 7}))
						got := fn.Call([]reflect.Value{
							reflect.ValueOf(context.Background()),
							reflect.ValueOf(backend.Scope{Account: account, Region: region}), q,
						})
						want := 1
						if region == "all" {
							want = 3
						}
						if !got[1].IsNil() || got[0].FieldByName("Items").Len() != want {
							t.Fatalf("list = %v", got)
						}
						seen := map[string]bool{}
						for range want {
							s := <-calls
							if s.Account != account || s.Region == "all" || seen[s.Region] {
								t.Fatalf("scope = %+v", s)
							}
							seen[s.Region] = true
						}
						if region != "all" && !seen[region] {
							t.Fatal("routed to another region")
						}
					})
				}
			}
		})
	}
}

func TestAllStartsInParallelAndRetainsEveryFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	started, release := make(chan struct{}, 3), make(chan struct{})
	set := newSet(t, catalog(), func(_ context.Context, _, _ string, s backend.Scope, _, dst any) error {
		started <- struct{}{}
		<-release
		if s.Region != "pve-b-1" {
			return errors.New("https://user:credential@internal/token?secret=canary")
		}
		dst.(*resource.Page[resource.Instance]).Items = []resource.Instance{{}}
		return nil
	})
	done := make(chan resource.Page[resource.Instance], 1)
	go func() {
		p, _ := set.Compute.DescribeInstances(ctx, backend.Scope{Region: "all"}, resource.InstanceQuery{})
		done <- p
	}()
	for range 3 {
		select {
		case <-started:
		case <-ctx.Done():
			close(release)
			t.Fatal("regions did not start together")
		}
	}
	close(release)
	p := <-done
	if len(p.Items) != 1 || len(p.Partial) != 2 ||
		p.Partial[0].Region != "pve-a-1" || p.Partial[1].Region != "pve-c-1" {
		t.Fatalf("partial result = %+v", p)
	}
	for _, failure := range p.Partial {
		if failure.Error != "region unavailable" {
			t.Fatalf("unsafe error = %q", failure.Error)
		}
	}
}

type failedCatalog struct{ backend.RegionCatalog }

func (failedCatalog) ProxmoxRegions(context.Context) ([]backend.ProxmoxRegion, error) {
	return nil, errors.New("https://credential@internal/token")
}

func TestCatalogAndResolverFailuresAreSafe(t *testing.T) {
	set := newSet(t, failedCatalog{}, func(context.Context, string, string, backend.Scope, any, any) error {
		t.Fatal("unreadable catalog reached transport")
		return nil
	})
	_, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: "all"}, resource.InstanceQuery{})
	if resource.CodeOf(err) != resource.CodeUnavailable || strings.Contains(err.Error(), "credential") {
		t.Fatalf("catalog error = %v", err)
	}
	set, err = regionset.New(catalog(), func(ctx context.Context,
		_ backend.ProxmoxRegion,
	) (regionclient.Transport, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Error("resolver is outside the region budget")
		}
		return nil, errors.New("credential https://internal/token")
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		p, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: "all"}, resource.InstanceQuery{})
		if err != nil || len(p.Partial) != 3 {
			t.Fatalf("resolver failures = %+v, %v", p, err)
		}
		for _, failure := range p.Partial {
			if failure.Error != "region unavailable" {
				t.Fatalf("unsafe resolver error = %q", failure.Error)
			}
		}
	}
}

func TestStalledServerReturnsOtherRegionsWithinEightSeconds(t *testing.T) {
	stalled := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer stalled.Close()
	set := newSet(t, catalog(), func(ctx context.Context, _, _ string, s backend.Scope, _, dst any) error {
		if s.Region != "pve-c-1" {
			dst.(*resource.Page[resource.Instance]).Items = []resource.Instance{{}}
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, stalled.URL, nil)
		if err != nil {
			return err
		}
		res, err := stalled.Client().Do(req)
		if err == nil {
			res.Body.Close()
		}
		return err
	})
	start := time.Now()
	p, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: "all"}, resource.InstanceQuery{})
	if err != nil || time.Since(start) >= 8*time.Second || len(p.Items) != 2 || len(p.Partial) != 1 ||
		p.Partial[0].Region != "pve-c-1" || p.Partial[0].Error != "region timed out" {
		t.Fatalf("elapsed=%s page=%+v err=%v", time.Since(start), p, err)
	}
}

func TestPaginationKeepsAllRegionCursorsAndRetriesFailures(t *testing.T) {
	calls := make(chan string, 20)
	first := true
	set := newSet(t, catalog(), func(_ context.Context, _, _ string, s backend.Scope, q, dst any) error {
		token := q.(resource.InstanceQuery).Page.Token
		calls <- s.Region + ":" + token
		if first && s.Region == "pve-c-1" {
			return errors.New("offline")
		}
		p := dst.(*resource.Page[resource.Instance])
		p.Items = []resource.Instance{{}}
		if token == "" {
			p.NextToken = "opaque:token"
		}
		return nil
	})
	for _, region := range []string{"pve-a-1", "all"} {
		first = true
		scope := backend.Scope{Region: region}
		p, err := set.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
		if err != nil || p.NextToken == "" {
			t.Fatalf("first page = %+v, %v", p, err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(p.NextToken)
		if !strings.HasPrefix(string(raw), region+":") {
			t.Fatalf("token = %s", raw)
		}
		first = false
		p, err = set.Compute.DescribeInstances(t.Context(), scope,
			resource.InstanceQuery{Page: resource.PageRequest{Token: p.NextToken}})
		if err != nil || len(p.Partial) != 0 {
			t.Fatalf("resumed = %+v, %v", p, err)
		}
		if region == "all" {
			if p.NextToken == "" || len(p.Items) != 3 {
				t.Fatalf("lost a pending region: %+v", p)
			}
			p, err = set.Compute.DescribeInstances(t.Context(), scope,
				resource.InstanceQuery{Page: resource.PageRequest{Token: p.NextToken}})
		}
		if err != nil || p.NextToken != "" || len(p.Items) != 1 {
			t.Fatalf("last page = %+v, %v", p, err)
		}
	}
	close(calls)
	seen := map[string]int{}
	for call := range calls {
		seen[call]++
	}
	for _, r := range []string{"pve-a-1", "pve-b-1", "pve-c-1"} {
		if seen[r+":opaque:token"] == 0 {
			t.Fatalf("cursor never resumed: %v", seen)
		}
	}
}

func TestInvalidTokensAndUnknownRegionsNeverReachTransport(t *testing.T) {
	set := newSet(t, catalog(), func(context.Context, string, string, backend.Scope, any, any) error {
		t.Fatal("invalid input reached transport")
		return nil
	})
	for _, c := range []struct {
		region, token string
	}{
		{"missing", ""},
		{"", ""},
		{"pve-a-1", "malformed!"},
		{"pve-a-1", base64.RawURLEncoding.EncodeToString([]byte("pve-b-1:token"))},
		{"all", base64.RawURLEncoding.EncodeToString([]byte(`all:{"missing":"secret"}`))},
		{"all", base64.RawURLEncoding.EncodeToString([]byte(`all:garbage`))},
		{"pve-a-1", strings.Repeat("x", (1<<20)+1)},
		{"pve-a-1", base64.RawURLEncoding.EncodeToString([]byte("pve-a-1:" + strings.Repeat("x", 4097)))},
		{"pve-a-1", base64.RawURLEncoding.EncodeToString([]byte("pve-a-1:\xff"))},
		{"pve-a-1", base64.RawURLEncoding.EncodeToString([]byte("pve-a-1:\n"))},
		{"all", base64.RawURLEncoding.EncodeToString([]byte(`all:{"pve-a-1":"\u0000"}`))},
		{"all", base64.RawURLEncoding.EncodeToString([]byte(`all:{"pve-a-1":"` + strings.Repeat("x", 4097) + `"}`))},
	} {
		_, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: c.region},
			resource.InstanceQuery{Page: resource.PageRequest{Token: c.token}})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("region=%s tokenBytes=%d: %v", c.region, len(c.token), err)
		}
	}
}

func TestConcreteRegionFailureIsPublic(t *testing.T) {
	for _, failure := range []error{
		errors.New("https://credential@internal/token"),
		context.DeadlineExceeded,
		resource.Invalid("filter", "unknown filter"),
	} {
		set := newSet(t, catalog(), func(context.Context, string, string, backend.Scope, any, any) error {
			return failure
		})
		_, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: "pve-a-1"}, resource.InstanceQuery{})
		var domain *resource.Error
		if !errors.As(err, &domain) || strings.Contains(err.Error(), "credential") {
			t.Fatalf("unsafe error = %v", err)
		}
		if resource.CodeOf(failure) == resource.CodeInvalidArgument && !errors.Is(err, failure) {
			t.Fatalf("lost public validation error: %v", err)
		}
	}
}

func TestCancellationBoundsUncooperativeTransport(t *testing.T) {
	started, release := make(chan struct{}, 3), make(chan struct{})
	defer close(release)
	set := newSet(t, catalog(), func(context.Context, string, string, backend.Scope, any, any) error {
		started <- struct{}{}
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := set.Compute.DescribeInstances(ctx, backend.Scope{Region: "all"}, resource.InstanceQuery{})
		done <- err
	}()
	for range 3 {
		<-started
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestCatalogRefreshAndNonListReads(t *testing.T) {
	cat := backend.NewStaticRegions(nil, nil)
	set := newSet(t, cat, func(_ context.Context, service, method string, s backend.Scope, _, _ any) error {
		if s.Region != "pve-new-1" || service != "Storage" || method != "GetBucket" {
			return fmt.Errorf("wrong route: %s.%s %+v", service, method, s)
		}
		return nil
	})
	cat.AddProxmoxRegion(backend.ProxmoxRegion{Name: "pve-new-1"})
	_, err := set.Storage.GetBucket(t.Context(), backend.Scope{Region: "pve-new-1"}, resource.BucketName{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = set.Storage.GetBucket(t.Context(), backend.Scope{Region: "all"}, resource.BucketName{})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("unscoped detail read = %v", err)
	}
	if _, err := regionset.New(nil, nil); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("nil configuration = %v", err)
	}
}
