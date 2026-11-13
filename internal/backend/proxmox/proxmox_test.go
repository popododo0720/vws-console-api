package proxmox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func scenario() pvefake.Scenario {
	return pvefake.Scenario{
		Version: pvefake.Version{Version: "9.2", Release: "9.2"}, Cluster: "test",
		Nodes:    []pvefake.Node{{Name: "pve1"}},
		Storages: []pvefake.Storage{{Node: "pve1", Name: "local"}},
		Roles:    []pvefake.Role{{ID: "PVEAuditor", Privs: []string{"Sys.Audit", "Datastore.Audit", "VM.Audit"}}},
		Tokens: []pvefake.Token{{
			ID: "vws@pve!inventory", Secret: "fake-secret",
			ACL: []pvefake.ACE{{Path: "/", Role: "PVEAuditor"}},
		}},
	}
}

func serve(t *testing.T, s pvefake.Scenario) (*pveclient.Client, *pvefake.Fake) {
	t.Helper()
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(func() {
		if violations := f.PoolWriteViolations(); len(violations) != 0 {
			t.Errorf("forbidden pool writes: %v", violations)
		}
		for _, request := range f.Requests() {
			if !strings.HasPrefix(request, "GET ") {
				t.Errorf("read-only package issued %s", request)
			}
		}
	})
	t.Cleanup(srv.Close)
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: s.Tokens[0].ID,
		Secret: pveclient.Secret(s.Tokens[0].Secret), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func registration() Registration {
	return Registration{Region: backend.ProxmoxRegion{Name: "pve-test-1"}, ClusterName: "test"}
}

func TestStartupChecks(t *testing.T) {
	for _, privilege := range []string{
		"VM.Allocate", "VM.PowerMgmt", "VM.Config.CPU", "VM.Config.Future",
		"VM.Snapshot", "VM.Console", "Permissions.Modify", "Pool.Allocate", "Sys.Modify", "Datastore.Allocate",
		"Sys.Console", "Future.Privilege",
	} {
		t.Run(privilege, func(t *testing.T) {
			s := scenario()
			s.Roles = append(s.Roles, pvefake.Role{ID: "Danger", Privs: []string{privilege}})
			propagate := false
			s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/vms/100", Role: "Danger", Propagate: &propagate})
			c, _ := serve(t, s)
			b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
			if err == nil || b != nil || !strings.Contains(err.Error(), privilege) {
				t.Fatalf("backend=%v err=%v", b, err)
			}
		})
	}
	t.Run("cluster mismatch", func(t *testing.T) {
		c, _ := serve(t, scenario())
		reg := registration()
		reg.ClusterName = "elsewhere"
		b, err := New(t.Context(), c, reg, RegionConfig{ReadOnly: true})
		if err == nil || b != nil || !strings.Contains(err.Error(), "cluster_name") {
			t.Fatalf("backend=%v err=%v", b, err)
		}
	})
	t.Run("standalone", func(t *testing.T) {
		s := scenario()
		s.Cluster = ""
		c, _ := serve(t, s)
		b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := b.RegionCapabilities(t.Context(), registration().Region.Name)
		if err != nil || doc.Cluster.Name != "test" {
			t.Fatalf("doc=%v err=%v", doc, err)
		}
	})
	t.Run("unknown storage", func(t *testing.T) {
		c, _ := serve(t, scenario())
		cfg := RegionConfig{ReadOnly: true, Storages: map[string]string{"gp3": "missing"}}
		_, err := New(t.Context(), c, registration(), cfg)
		if err == nil || !strings.Contains(err.Error(), "storages.gp3") || !strings.Contains(err.Error(), "missing") {
			t.Fatal(err)
		}
	})
	t.Run("canceled startup", func(t *testing.T) {
		c, _ := serve(t, scenario())
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if b, err := New(ctx, c, registration(), RegionConfig{ReadOnly: true}); err == nil || b != nil {
			t.Fatalf("backend=%v err=%v", b, err)
		}
	})
}

func TestCapabilitiesLiveTestsFromRegionYAML(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       bool
	}{
		{"true", "read_only: true\nlive_tests: true\n", true},
		{"false", "read_only: true\nlive_tests: false\n", false},
		{"absent", "read_only: true\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseRegion([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			c, _ := serve(t, scenario())
			b, err := New(t.Context(), c, registration(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := b.RegionCapabilities(t.Context(), registration().Region.Name)
			if err != nil || doc.Features.LiveTests != tc.want {
				t.Fatalf("features=%+v err=%v; want liveTests=%v", doc.Features, err, tc.want)
			}
		})
	}
}

func TestReadOnlyBackendEveryMethod(t *testing.T) {
	c, f := serve(t, scenario())
	for range 2 {
		cfg := RegionConfig{ReadOnly: true, Storages: map[string]string{"gp3": "local"}}
		b, err := New(t.Context(), c, registration(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := b.RegionCapabilities(t.Context(), registration().Region.Name)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, a := range resource.Actions() {
			if doc.Mutation(a).State != resource.ActionUnsupported {
				t.Fatal(a)
			}
		}
		for _, r := range resource.ReadActions() {
			want := resource.ActionEmpty
			if r.CapabilityKey() == "ec2:DescribeVpcs" || r.CapabilityKey() == "ec2:DescribeSubnets" {
				want = resource.ActionPartial
			}
			if r.CapabilityKey() == "ec2:DescribeInstances" || r.CapabilityKey() == "ec2:DescribeVolumes" ||
				r.CapabilityKey() == "ec2:DescribeSnapshots" {
				want = resource.ActionSupported
			}
			if doc.Read(r).State != want {
				t.Fatal(r)
			}
		}
		for _, service := range []any{b.Set().Compute, b.Set().Network, b.Set().Storage} {
			value := reflect.ValueOf(service)
			for i := 0; i < value.NumMethod(); i++ {
				name := value.Type().Method(i).Name
				if name == "Set" || name == "RegionCapabilities" || name == "Status" {
					continue
				}
				method := value.Method(i)
				args := []reflect.Value{reflect.ValueOf(t.Context())}
				for j := 1; j < method.Type().NumIn(); j++ {
					args = append(args, reflect.Zero(method.Type().In(j)))
				}
				out := method.Call(args)
				last := out[len(out)-1]
				switch {
				case name == "RecoverLaunch":
					if last.IsNil() || !errors.Is(last.Interface().(error), ErrInput) {
						t.Fatalf("%s with an empty key: %v", name, out)
					}
				case name == "PoolExists":
					if last.IsNil() || out[0].Bool() || resource.CodeOf(last.Interface().(error)) != resource.CodeUnavailable {
						t.Fatalf("%s with an empty pool: %v", name, out)
					}
				case name == "GetAllocation":
					if last.IsNil() || !out[0].IsZero() ||
						resource.CodeOf(last.Interface().(error)) != resource.CodePermissionDenied {
						t.Fatalf("%s without pool visibility: %v", name, out)
					}
				case strings.HasPrefix(name, "Describe"), strings.HasPrefix(name, "List"):
					if !last.IsNil() || !out[0].IsZero() {
						t.Fatalf("%s: %v", name, out)
					}
				case strings.HasPrefix(name, "Get"):
					if last.IsNil() || resource.CodeOf(last.Interface().(error)) != resource.CodeNotFound {
						t.Fatalf("%s: %v", name, out)
					}
				default:
					if last.IsNil() {
						t.Fatalf("%s succeeded", name)
					}
					e, _ := errors.AsType[*resource.Error](last.Interface().(error))
					if !resource.IsUnsupported(e) {
						t.Fatalf("%s: %v", name, out)
					}
				}
			}
		}
	}
	methods := f.RequestMethods()
	if len(methods) == 0 {
		t.Fatal("startup made no requests")
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("non-GET request: %s", method)
		}
	}
}

func TestRegionSchema(t *testing.T) {
	for _, field := range []string{"unknown", "region", "name", "cluster_name", "zones", "pve_api_url", "token_secret"} {
		if _, err := ParseRegion([]byte(field + ": value\n")); err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("%s: %v", field, err)
		}
	}
	for _, text := range []string{
		"templates: {unknown: true}", "read_only: true\nread_only: false", "read_only: true\n---\nregion: bad",
	} {
		if _, err := ParseRegion([]byte(text)); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	cfg, err := ParseRegion([]byte(`read_only: true
storages: {gp3: local}
templates: {pool: vws-images, tag: image}
instance_types: {vws.small: {cores: 1, memory_mib: 1024}}
subnets: {vmbr0: {cidr: 192.0.2.0/24, gateway: 192.0.2.1, ip_range: 192.0.2.2-192.0.2.20, mode: direct}}
default_bridge: vmbr0
default_project: default
pools: {default: vws-default}
scheduler: {policy: spread, host_reserve_mib: 2048, mem_overcommit: 1, cpu_overcommit: 4}
linked_clones: false
`))
	if err != nil || !cfg.ReadOnly || cfg.Storages["gp3"] != "local" {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	if _, err := LoadRegion(t.TempDir() + "/missing.yaml"); err == nil {
		t.Fatal("missing file accepted")
	}
}
