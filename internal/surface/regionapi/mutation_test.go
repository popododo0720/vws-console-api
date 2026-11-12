package regionapi

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func mutationWorld() backend.Set {
	return fake.New(fake.Options{
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }, Entropy: &fake.Sequence{},
	}).Set()
}

func TestMutationContractRoundTrip(t *testing.T) {
	caps, err := (backend.AllSupported{Kind: resource.RegionKindProxmox}).RegionCapabilities(t.Context(), "pve-test")
	if err != nil {
		t.Fatal(err)
	}
	backendtest.Run(t, func() backend.Set {
		c, _ := loopback(t, config(mutationWorld()))
		set, err := regionclient.New(c)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}, caps)
}

func TestEveryMutationRoundTrips(t *testing.T) {
	for _, service := range []struct {
		name string
		typ  reflect.Type
	}{
		{"Compute", reflect.TypeFor[backend.Compute]()},
		{"Network", reflect.TypeFor[backend.Network]()},
		{"Storage", reflect.TypeFor[backend.Storage]()},
	} {
		for i := 0; i < service.typ.NumMethod(); i++ {
			method := service.typ.Method(i)
			if strings.HasPrefix(method.Name, "Describe") || strings.HasPrefix(method.Name, "Get") ||
				strings.HasPrefix(method.Name, "List") {
				continue
			}
			t.Run(service.name+"/"+method.Name, func(t *testing.T) {
				local, served := mutationWorld(), mutationWorld()
				c, _ := loopback(t, config(served))
				remote, err := regionclient.New(c)
				if err != nil {
					t.Fatal(err)
				}
				clients := func(set backend.Set) reflect.Value {
					return reflect.ValueOf(set).FieldByName(service.name).Elem()
				}
				invoke := func(set backend.Set) []reflect.Value {
					args := []reflect.Value{reflect.ValueOf(t.Context())}
					for j := 1; j < method.Type.NumIn(); j++ {
						typ := method.Type.In(j)
						value := reflect.New(typ).Elem()
						fillMutationRequest(t, value)
						switch typ {
						case reflect.TypeFor[backend.Scope]():
							value = reflect.ValueOf(testScope(t))
						case reflect.TypeFor[backend.Mutation]():
							value = reflect.ValueOf(backend.Mutation{
								Scope: testScope(t), Key: "same-key", Fingerprint: "same-fingerprint", MintedToken: true,
							})
						case reflect.TypeFor[io.Reader]():
							value = reflect.ValueOf(strings.NewReader(""))
						}
						args = append(args, value)
					}
					return clients(set).MethodByName(method.Name).Call(args)
				}
				for range 2 {
					want, got := invoke(local), invoke(remote)
					for j := range want {
						if j == len(want)-1 {
							var a, b error
							if !want[j].IsNil() {
								a = want[j].Interface().(error)
							}
							if !got[j].IsNil() {
								b = got[j].Interface().(error)
							}
							aJSON, _ := json.Marshal(resource.AsError(a))
							bJSON, _ := json.Marshal(resource.AsError(b))
							if string(aJSON) != string(bJSON) {
								t.Fatalf("error changed: direct=%v remote=%v", a, b)
							}
						} else if !reflect.DeepEqual(want[j].Interface(), got[j].Interface()) {
							t.Fatalf("result changed: direct=%+v remote=%+v", want[j], got[j])
						}
					}
				}
			})
		}
	}
}

func fillMutationRequest(t *testing.T, value reflect.Value) {
	t.Helper()
	names := map[reflect.Type]string{
		reflect.TypeFor[resource.InstanceID]():      "i-0123456789abcdef0",
		reflect.TypeFor[resource.VolumeID]():        "vol-0123456789abcdef0",
		reflect.TypeFor[resource.SnapshotID]():      "snap-0123456789abcdef0",
		reflect.TypeFor[resource.ImageID]():         "ami-0123456789abcdef0",
		reflect.TypeFor[resource.VpcID]():           "vpc-0123456789abcdef0",
		reflect.TypeFor[resource.SubnetID]():        "subnet-0123456789abcdef0",
		reflect.TypeFor[resource.SecurityGroupID](): "sg-0123456789abcdef0",
		reflect.TypeFor[resource.AddressID]():       "eipalloc-0123456789abcdef0",
		reflect.TypeFor[resource.BucketName]():      "test-bucket", reflect.TypeFor[resource.ObjectKey](): "test-key",
	}
	if text, ok := names[value.Type()]; ok {
		if err := json.Unmarshal([]byte(`"`+text+`"`), value.Addr().Interface()); err != nil {
			t.Fatal(err)
		}
	} else if value.Type() == reflect.TypeFor[resource.CreateKeyPairRequest]() {
		value.Set(reflect.ValueOf(resource.CreateKeyPairRequest{Name: "key", Type: resource.KeyTypeEd25519}))
	} else if value.Kind() == reflect.Struct {
		for i := 0; i < value.NumField(); i++ {
			if value.Field(i).CanSet() {
				fillMutationRequest(t, value.Field(i))
			}
		}
	}
}

type captureMutation struct {
	backend.Compute
	got chan backend.Mutation
}

func (c captureMutation) CreateVolume(ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest) (
	resource.Accepted[resource.Volume], error,
) {
	c.got <- m
	return c.Compute.CreateVolume(ctx, m, req)
}

func TestGlobalKernelMutationArrivesByteIdentical(t *testing.T) {
	set := mutationWorld()
	captured := make(chan backend.Mutation, 1)
	set.Compute = captureMutation{set.Compute, captured}
	c, _ := loopback(t, config(set))
	routed, err := regionset.New(backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test"}}, nil),
		func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	caller := resource.Caller{Account: testScope(t).Account, Region: "pve-test", Principal: "principal"}
	token, err := resource.Parse[resource.ClientToken]("transport-test")
	if err != nil {
		t.Fatal(err)
	}
	req := resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2}
	direct := cloud.New(cloud.Config{Backends: set})
	want, err := direct.CreateVolume(t.Context(), caller, token, req)
	if err != nil {
		t.Fatal(err)
	}
	original := <-captured
	if len(original.Key) != 64 || len(original.Fingerprint) != 64 {
		t.Fatalf("kernel hashes missing: %+v", original)
	}
	global := cloud.New(cloud.Config{Backends: routed})
	got, err := global.CreateVolume(t.Context(), caller, token, req)
	if err != nil || !reflect.DeepEqual(want, got) || original != <-captured {
		t.Fatalf("kernel mutation changed: result=%+v error=%v", got, err)
	}
	original.MintedToken = true
	if _, err := routed.Compute.CreateVolume(t.Context(), original, req); err != nil {
		t.Fatal(err)
	}
	if got := <-captured; got != original {
		t.Fatalf("minted mutation changed: %+v", got)
	}
}

func TestMutationGateAndObjectBound(t *testing.T) {
	for _, peer := range []string{"", "other-node"} {
		cfg := config(mutationWorld())
		cfg.Gate = &mutationGate{peer: peer}
		c, _ := loopback(t, cfg)
		remote, err := regionclient.New(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remote.Compute.CreateVolume(t.Context(), backend.Mutation{Scope: testScope(t)},
			resource.CreateVolumeRequest{SizeGiB: 8})
		if (resource.CodeOf(err) == resource.CodeUnavailable) != (peer != "") {
			t.Fatalf("peer %q mutation error = %v", peer, err)
		}
		bucket, _ := resource.Parse[resource.BucketName]("test-bucket")
		if _, err := remote.Storage.CreateBucket(t.Context(), testScope(t), bucket); peer != "" &&
			resource.CodeOf(err) != resource.CodeUnavailable {
			t.Fatalf("storage bypassed follower gate: %v", err)
		}
		_, err = remote.Storage.PutObject(t.Context(), testScope(t), resource.PutObjectRequest{},
			strings.NewReader(strings.Repeat("x", resource.MaxObjectBytes+1)))
		if resource.CodeOf(err) != resource.CodePayloadTooLarge {
			t.Fatalf("oversized object error = %v", err)
		}
	}
}
