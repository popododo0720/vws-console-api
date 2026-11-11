package proxmox

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestRegionalInstanceTypes(t *testing.T) {
	small := []resource.InstanceType{
		{Name: "vws.small", VCPUs: 1, MemoryMiB: 1024},
		{Name: "vws.medium", VCPUs: 2, MemoryMiB: 4096},
	}
	all := append(append([]resource.InstanceType{}, small...),
		resource.InstanceType{Name: "vws.large", VCPUs: 4, MemoryMiB: 8192},
		resource.InstanceType{Name: "vws.xlarge", VCPUs: 8, MemoryMiB: 16384},
		resource.InstanceType{Name: "vws.2xlarge", VCPUs: 16, MemoryMiB: 32768},
		resource.InstanceType{Name: "vws.4xlarge", VCPUs: 32, MemoryMiB: 65536},
		resource.InstanceType{Name: "vws.8xlarge", VCPUs: 64, MemoryMiB: 131072},
	)
	for _, tc := range []struct {
		name  string
		nodes []pvefake.Node
		yaml  string
		want  []resource.InstanceType
	}{
		{"live capacity", []pvefake.Node{{Name: "pve1", MaxCPU: 4, MaxMem: 8 << 30}}, "", small},
		{"full capacity", []pvefake.Node{{Name: "pve1", MaxCPU: 64, MaxMem: 256 << 30}}, "", all},
		{
			"restriction",
			[]pvefake.Node{{Name: "pve1", MaxCPU: 64, MaxMem: 256 << 30}},
			"instance_types: {vws.medium: {cores: 2, memory_mib: 4096}}", small[1:],
		},
		{
			"restriction still needs fit",
			[]pvefake.Node{{Name: "pve1", MaxCPU: 4, MaxMem: 8 << 30}},
			"instance_types: {vws.large: {cores: 4, memory_mib: 8192}}",
			[]resource.InstanceType{},
		},
		{
			"empty restriction",
			[]pvefake.Node{{Name: "pve1", MaxCPU: 64, MaxMem: 256 << 30}},
			"instance_types: {}",
			[]resource.InstanceType{},
		},
		{
			"custom reserve",
			[]pvefake.Node{{Name: "pve1", MaxCPU: 4, MaxMem: 8 << 30}},
			"scheduler: {host_reserve_mib: 4097}", small[:1],
		},
		{"missing stats", []pvefake.Node{{Name: "pve1"}}, "", []resource.InstanceType{}},
		{"missing memory", []pvefake.Node{{Name: "pve1", MaxCPU: 64}}, "", []resource.InstanceType{}},
		{"missing cpu", []pvefake.Node{{Name: "pve1", MaxMem: 256 << 30}}, "", []resource.InstanceType{}},
		{"same node must fit", []pvefake.Node{
			{Name: "pve1", MaxCPU: 64, MaxMem: 3 << 30},
			{Name: "pve2", MaxCPU: 2, MaxMem: 256 << 30},
		}, "", small},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario()
			s.Nodes = tc.nodes
			c, _ := serve(t, s)
			cfg, err := ParseRegion([]byte("read_only: true\n" + tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			reg := registration()
			reg.Region.Name = resource.RegionName
			b, err := New(t.Context(), c, reg, cfg)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := b.RegionCapabilities(t.Context(), reg.Region.Name)
			if err != nil {
				t.Fatal(err)
			}
			wantDoc := []resource.RegionInstanceType{}
			for _, typ := range tc.want {
				wantDoc = append(wantDoc, resource.RegionInstanceType{
					InstanceType: typ.Name, VCPUs: typ.VCPUs, MemoryMiB: typ.MemoryMiB,
				})
			}
			if !reflect.DeepEqual(doc.InstanceTypes, wantDoc) {
				t.Fatalf("capabilities = %+v, want %+v", doc.InstanceTypes, wantDoc)
			}
			checkCatalogSurfaces(t, b, tc.want)
		})
	}
}

func checkCatalogSurfaces(t *testing.T, b *Backend, want []resource.InstanceType) {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	caller := resource.Caller{Account: account, Root: true, Principal: iam.RootARN(account)}
	auth := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	svc := cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b})
	ui := console.New(console.Config{Service: svc, IAM: auth, Auth: console.BearerTokens{"catalog": caller}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/instance-types", nil)
	req.Header.Set("Authorization", "Bearer catalog")
	rec := httptest.NewRecorder()
	ui.ServeHTTP(rec, req)
	var page resource.Page[resource.InstanceType]
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("console: %d %s, %v", rec.Code, rec.Body, err)
	}
	if !reflect.DeepEqual(page.Items, want) {
		t.Fatalf("console = %+v, want %+v", page.Items, want)
	}
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: auth,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
			Now: func() time.Time { return now }, Auth: iam.Authenticator(auth),
		}),
	})
	for _, name := range []string{"", "vws.8xlarge"} {
		form := url.Values{"Action": {"DescribeInstanceTypes"}, "Version": {ec2query.Version}}
		if name != "" {
			form.Set("InstanceType.1", name)
		}
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://localhost/",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		query.ServeHTTP(rec, req)
		expected := []resource.InstanceType{}
		for _, typ := range want {
			if name == "" || typ.Name == name {
				expected = append(expected, typ)
			}
		}
		if name != "" && len(expected) == 0 {
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "<Code>InvalidInstanceType</Code>") {
				t.Fatalf("unavailable type: %d %s", rec.Code, rec.Body)
			}
			continue
		}
		var doc struct {
			Items []struct {
				Name   string `xml:"instanceType"`
				VCPUs  int    `xml:"vCpuInfo>defaultVCpus"`
				Memory int    `xml:"memoryInfo>sizeInMiB"`
			} `xml:"instanceTypeSet>item"`
		}
		if err := xml.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("EC2: %d %s, %v", rec.Code, rec.Body, err)
		}
		got := []resource.InstanceType{}
		for _, typ := range doc.Items {
			got = append(got, resource.InstanceType{Name: typ.Name, VCPUs: typ.VCPUs, MemoryMiB: typ.Memory})
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("EC2 = %+v, want %+v", got, expected)
		}
	}
}

func TestNearestInstanceType(t *testing.T) {
	for _, tc := range []struct {
		cpu, memory int
		want        string
	}{
		{2, 4096, "vws.medium"},
		{2, 4500, "vws.medium"},
		{2, 6000, "custom"},
		{2, 3584, "vws.medium"},
		{2, 4608, "vws.medium"},
		{2, 3583, "custom"},
		{2, 4609, "custom"},
		{1, 1024, "vws.small"},
		{4, 8192, "vws.large"},
		{8, 16384, "vws.xlarge"},
		{16, 32768, "vws.2xlarge"},
		{32, 65536, "vws.4xlarge"},
		{64, 131072, "vws.8xlarge"},
		{3, 4096, "custom"},
		{0, 0, "custom"},
		{2, -1, "custom"},
	} {
		if got := NearestInstanceType(tc.cpu, tc.memory); got != tc.want {
			t.Errorf("%d/%d = %s, want %s", tc.cpu, tc.memory, got, tc.want)
		}
	}
}

func TestInstanceTypeAliases(t *testing.T) {
	typ, ok := ResolveInstanceType("t3.micro")
	if !ok || typ != (resource.InstanceType{Name: "vws.small", VCPUs: 1, MemoryMiB: 1024}) {
		t.Fatalf("t3.micro = %+v, %v", typ, ok)
	}
	for _, expected := range InstanceTypes() {
		if typ, ok := ResolveInstanceType(expected.Name); !ok || typ != expected {
			t.Fatalf("%s = %+v, %v", expected.Name, typ, ok)
		}
	}
	if _, ok := ResolveInstanceType("unknown"); ok {
		t.Fatal("unknown type resolved")
	}
}

func TestInstanceTypeConfigurationRefusesDefinitions(t *testing.T) {
	c, _ := serve(t, scenario())
	for _, text := range []string{
		"instance_types: {custom: {cores: 2, memory_mib: 4096}}",
		"instance_types: {vws.medium: {cores: 3, memory_mib: 4096}}",
		"instance_types: {vws.medium: {cores: 2, memory_mib: 6000}}",
		"scheduler: {host_reserve_mib: -1}",
	} {
		cfg, err := ParseRegion([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(t.Context(), c, registration(), cfg); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestInstanceTypeCapacityFailure(t *testing.T) {
	c, _ := serve(t, scenario())
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.RegionCapabilities(ctx, registration().Region.Name); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"capacity denied"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	b.client, err = pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory", Secret: "fake-secret", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.RegionCapabilities(t.Context(), registration().Region.Name)
	pveErr, ok := errors.AsType[*pveclient.HTTPError](err)
	if !ok || pveErr.Status != http.StatusForbidden || !strings.Contains(err.Error(), "list node capacity") {
		t.Fatalf("PVE error = %v", err)
	}
}
