package proxmox

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func imageScenario() pvefake.Scenario {
	s := inventoryScenario()
	s.VMs[0].Template = true
	s.VMs[0].Name = "debian"
	s.VMs[0].Config["description"] = "Debian base"
	s.VMs[0].Config["boot"] = "order=ide2;scsi0;net0"
	s.VMs[0].Config["ide2"] = "local:iso/installer.iso,media=cdrom"
	s.VMs[0].Config["scsi0"] = "local:vm-100-disk-0,size=8193M"
	return s
}

func TestImageInventoryFieldsAndRestart(t *testing.T) {
	c, f := serve(t, imageScenario())
	ids, _ := NewIDs("test")
	id, _ := ids.Image("5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10")
	want := resource.Image{
		ID: id, OwnerID: inventoryScope().Account, Name: "debian",
		State: "available", Description: "Debian base", SizeGiB: 9,
	}
	for range 2 {
		b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			page, err := b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{})
			if err != nil || !reflect.DeepEqual(page.Items, []resource.Image{want}) || page.NextToken != "" {
				t.Fatalf("images = %+v, %v; want %+v", page, err, want)
			}
		}
		doc, err := b.RegionCapabilities(t.Context(), b.region)
		if err != nil || doc.Actions["ec2:DescribeImages"].State != resource.ActionSupported {
			t.Fatalf("image capability = %+v, %v", doc, err)
		}
		instances, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
		if err != nil || len(instances.Items) != 0 {
			t.Fatalf("template listed as instance: %+v, %v", instances, err)
		}
	}
	for _, method := range f.RequestMethods() {
		if method != http.MethodGet {
			t.Fatalf("image read issued %s", method)
		}
	}
}

func TestImageInventoryPoolBoundaries(t *testing.T) {
	s := imageScenario()
	s.VMs[0].Pool = "parent/child"
	for i, pool := range []string{"999999999999", "", "public"} {
		vm := s.VMs[0]
		vm.VMID, vm.Pool = 200+i, pool
		s.VMs = append(s.VMs, vm)
	}
	b, f := networkBackend(t, s, RegionConfig{
		Pools: map[string]string{"123456789012": "parent/child"}, DefaultProject: "123456789012",
		Templates: TemplateConfig{Pool: "public"},
	})
	foreign, _ := resource.Parse[resource.AccountID]("999999999999")
	ids, _ := NewIDs("test")
	id, _ := ids.Image(configUUID(pveclient.VMConfig{SMBIOS1: s.VMs[0].Config["smbios1"]}))
	for _, pool := range []string{"parent/child", "999999999999", ""} {
		if err := f.MoveVM(100, pool); err != nil {
			t.Fatal(err)
		}
		page, err := b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{})
		want := 1
		if pool != "999999999999" {
			want++
		}
		if err != nil || len(page.Items) != want {
			t.Fatalf("pool %q images = %+v, %v", pool, page, err)
		}
		page, err = b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{Owner: foreign})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("foreign owner images = %+v, %v", page, err)
		}
	}
	for _, request := range f.Requests() {
		if strings.Contains(request, "/qemu/200/") || strings.Contains(request, "/qemu/202/") {
			t.Fatalf("read outside caller pools: %s", request)
		}
	}
	s.VMs = s.VMs[1:2]
	b, _ = networkBackend(t, s, RegionConfig{})
	if _, err := b.DescribeImages(t.Context(), inventoryScope(),
		resource.ImageQuery{IDs: []resource.ImageID{id}}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("foreign image lookup = %v", err)
	}
	s.Roles[0].Privs = slices.DeleteFunc(s.Roles[0].Privs, func(p string) bool { return p == "Pool.Audit" })
	b, _ = networkBackend(t, s, RegionConfig{DefaultProject: "123456789012"})
	_, err := b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{})
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("hidden pool names exposed images: %v", err)
	}
}

func TestImageInventorySkipsInvalidTemplates(t *testing.T) {
	s := imageScenario()
	for i, cfg := range []map[string]string{
		{}, {"smbios1": "uuid=bad"}, {"smbios1": s.VMs[0].Config["smbios1"], "tags": "vws.holder"},
	} {
		s.VMs = append(s.VMs, pvefake.VM{
			VMID: 200 + i, Node: "pve1", Pool: "123456789012", Template: true, Config: cfg,
		})
	}
	vm := s.VMs[0]
	vm.VMID, vm.Template = 300, false
	s.VMs = append(s.VMs, vm)
	vm.VMID, vm.Template, vm.Tags = 301, true, "vws.holder"
	s.VMs = append(s.VMs, vm)
	b, _ := networkBackend(t, s, RegionConfig{})
	page, err := b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("invalid template inventory = %+v, %v", page, err)
	}
	ids, _ := NewIDs("test")
	unknown, _ := ids.UnknownImage()
	if _, err := b.DescribeImages(t.Context(), inventoryScope(),
		resource.ImageQuery{IDs: []resource.ImageID{unknown}}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("unknown image = %v", err)
	}
}

func TestImageInventoryFiltersAndPaging(t *testing.T) {
	s := imageScenario()
	base := s.VMs[0]
	s.VMs = nil
	ids, _ := NewIDs("test")
	var matches []resource.ImageID
	for i := 100; i < 202; i++ {
		uuid := fmt.Sprintf("5f0c3e9a-8b5d-4b8e-9a51-%012d", i)
		vm := base
		vm.VMID = i
		vm.Config = map[string]string{"smbios1": "uuid=" + uuid}
		s.VMs = append(s.VMs, vm)
		if i >= 200 {
			id, _ := ids.Image(uuid)
			matches = append(matches, id)
		}
	}
	b, _ := networkBackend(t, s, RegionConfig{})
	for _, query := range []resource.ImageQuery{
		{}, {IDs: matches}, {Owner: inventoryScope().Account, IDs: matches},
	} {
		query.Page.Size = 100
		if len(query.IDs) != 0 {
			query.Page.Size = 1
		}
		seen := map[resource.ImageID]bool{}
		for {
			page, err := b.DescribeImages(t.Context(), inventoryScope(), query)
			if err != nil || len(page.Items) == 0 {
				t.Fatalf("page = %+v, %v", page, err)
			}
			for _, image := range page.Items {
				id := image.ID
				if seen[id] || len(query.IDs) != 0 && !slices.Contains(matches, id) {
					t.Fatalf("duplicate or unfiltered image %s", id)
				}
				seen[id] = true
			}
			query.Page.Token = page.NextToken
			if query.Page.Token == "" {
				break
			}
		}
		want := 102
		if len(query.IDs) != 0 {
			want = 2
		}
		if len(seen) != want {
			t.Fatalf("listed %d images, want %d", len(seen), want)
		}
	}
	for _, token := range []string{"../bad", "ami-00000000000000000"} {
		_, err := b.DescribeImages(t.Context(), inventoryScope(),
			resource.ImageQuery{Page: resource.PageRequest{Token: token}})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("invalid cursor %q = %v", token, err)
		}
	}
}

func TestImageInventoryFailures(t *testing.T) {
	for _, path := range []string{"/cluster/resources", "/nodes/pve1/qemu/100/config"} {
		s := imageScenario()
		s.Tokens[0].Secret = "test-secret"
		_, f := serve(t, s)
		c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api2/json"+path {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.ServeHTTP(w, r)
		})
		b, err := New(t.Context(), c, registration(), RegionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		ids, _ := NewIDs("test")
		id, _ := ids.Image("5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10")
		_, err = b.DescribeImages(t.Context(), inventoryScope(), resource.ImageQuery{IDs: []resource.ImageID{id}})
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("missing upstream error for %s: %v", path, err)
		}
		if strings.HasSuffix(path, "/config") && resource.CodeOf(err) != resource.CodeUnavailable {
			t.Fatalf("unreadable requested image = %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := b.DescribeImages(ctx, inventoryScope(), resource.ImageQuery{}); err == nil {
			t.Fatal("canceled image read succeeded")
		}
	}
}

func TestImageRootSize(t *testing.T) {
	for _, tc := range []struct {
		boot, disk, size string
		want             int64
	}{
		{"order=virtio0", "", "1.5G", 2},
		{"order=virtio0", "", "1T", 1024},
		{"", "virtio0", "1073741824", 1},
		{"order=net0", "", "8G", 0},
		{"", "", "8G", 0},
		{"order=virtio0", "", "", 0},
		{"order=virtio0", "", "bad", 0},
		{"order=virtio0", "", "-1G", 0},
		{"order=virtio0", "", "NaN", 0},
		{"order=virtio0", "", "1e100G", 0},
	} {
		t.Run(tc.boot+tc.disk+tc.size, func(t *testing.T) {
			cfg := pveclient.VMConfig{
				Boot: tc.boot, BootDisk: tc.disk,
				Drives: map[string]string{"virtio0": "local:vm-100-disk-0,size=" + tc.size},
			}
			if got := imageRootSize(cfg); got != tc.want {
				t.Fatalf("size = %d, want %d", got, tc.want)
			}
		})
	}
}
