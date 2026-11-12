package regionclient_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type transportFunc func(context.Context, string, string, backend.Scope, any, any) error

func (f transportFunc) Call(ctx context.Context, service, method string, scope, req, dst any) error {
	return f(ctx, service, method, scope.(backend.Scope), req, dst)
}

func services(set backend.Set) []struct {
	name  string
	value any
} {
	return []struct {
		name  string
		value any
	}{{"Compute", set.Compute}, {"Storage", set.Storage}, {"Network", set.Network}}
}

func isRead(method string) bool {
	return strings.HasPrefix(method, "Describe") || strings.HasPrefix(method, "Get") ||
		strings.HasPrefix(method, "List")
}

func TestEveryReadPreservesScopeQueryAndFailure(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account, Region: "pve-seoul-1"}
	failure := &resource.Error{Code: resource.CodeUnavailable, Message: "offline"}
	var wantService, wantMethod string
	var wantQuery any
	set, err := regionclient.New(transportFunc(func(ctx context.Context, service, method string,
		gotScope backend.Scope, query, _ any,
	) error {
		if service != wantService || method != wantMethod || gotScope != scope || !reflect.DeepEqual(query, wantQuery) {
			t.Fatalf("call = %s.%s %+v %#v", service, method, gotScope, query)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("read has no bounded deadline")
		}
		return failure
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services(set) {
		value := reflect.ValueOf(service.value)
		for i := 0; i < value.NumMethod(); i++ {
			method := value.Type().Method(i).Name
			if !isRead(method) {
				continue
			}
			t.Run(service.name+"/"+method, func(t *testing.T) {
				fn := value.MethodByName(method)
				q := reflect.New(fn.Type().In(2)).Elem()
				if q.Kind() == reflect.Struct {
					if page := q.FieldByName("Page"); page.IsValid() {
						page.Set(reflect.ValueOf(resource.PageRequest{Size: 7, Token: "opaque:region-token"}))
					}
				}
				wantService, wantMethod, wantQuery = service.name, method, q.Interface()
				result := fn.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(scope), q})
				err, ok := result[len(result)-1].Interface().(error)
				if !ok || !errors.Is(err, failure) {
					t.Fatalf("error = %v, want original failure", err)
				}
				for _, value := range result[:len(result)-1] {
					if !value.IsZero() {
						t.Fatalf("failed read returned a result: %v", value)
					}
				}
			})
		}
	}
}

func TestReadHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	set, err := regionclient.New(transportFunc(func(ctx context.Context, _, _ string, _ backend.Scope, _, _ any) error {
		return ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = set.Compute.DescribeInstances(ctx, backend.Scope{}, resource.InstanceQuery{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("read error = %v, want cancellation", err)
	}
}

func TestStorageMutationDeadline(t *testing.T) {
	calls := 0
	set, err := regionclient.New(transportFunc(func(
		ctx context.Context, _, _ string, _ backend.Scope, _, _ any,
	) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 60*time.Second || time.Until(deadline) < 55*time.Second {
			t.Fatal("storage write has no 60 s mutation deadline")
		}
		calls++
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	value := reflect.ValueOf(set.Storage)
	for _, name := range []string{"CreateBucket", "DeleteBucket", "PutObject", "DeleteObject"} {
		t.Run(name, func(t *testing.T) {
			fn := value.MethodByName(name)
			args := []reflect.Value{reflect.ValueOf(t.Context())}
			for j := 1; j < fn.Type().NumIn(); j++ {
				arg := reflect.Zero(fn.Type().In(j))
				if fn.Type().In(j) == reflect.TypeFor[io.Reader]() {
					arg = reflect.ValueOf(strings.NewReader(""))
				}
				args = append(args, arg)
			}
			result := fn.Call(args)
			if !result[len(result)-1].IsNil() {
				t.Fatalf("write error = %v", result[len(result)-1])
			}
		})
	}
	if calls != 4 {
		t.Fatalf("transport calls = %d, want 4", calls)
	}
}

func TestNilTransportIsRefused(t *testing.T) {
	if _, err := regionclient.New(nil); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("nil transport error = %v", err)
	}
}
