package proxmox

import (
	"fmt"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const testUUID = "11111111-2222-4333-8444-555555555555"

func TestFormulasArePinned(t *testing.T) {
	c := NewIDs("pve-seoul")
	str := func(id fmt.Stringer, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	inst := func(vm VM) string {
		id, _, err := c.Instance(vm)
		return str(id, err)
	}
	vol := func(serial string) string {
		id, _, err := c.Volume(serial, "local-lvm", "vm-100-disk-0")
		return str(id, err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"instance", inst(VM{UUID: testUUID, VMID: 100}), "i-ebebdf34c7d704a1b"},
		{"instance fallback", inst(VM{VMID: 100, Ctime: "1700000000"}), "i-c2572d9c894a53e0f"},
		{"instance vmid", inst(VM{VMID: 100}), "i-fc86d4095ce7cd74a"},
		{"image", str(c.Image(testUUID)), "ami-b55664fc143a968a7"},
		{"unknown image", str(c.UnknownImage()), "ami-76ae8c59cae0848c1"},
		{"snapshot", str(c.Snapshot(testUUID, "before-upgrade")), "snap-27a0d1f7e3a8e71dd"},
		{"reservation", str(c.Reservation("key1")), "r-74e47d2393c7d380d"},
		{"volume serial", c.VolumeSerial("key1", 0), "64789ba320027f896"},
		{"root volume serial", c.RootVolumeSerial(testUUID), "1242e29aa9300a558"},
		{"volume by serial", vol("64789ba320027f896"), "vol-64789ba320027f896"},
		{"volume by name", vol(""), "vol-a246dac826e6d32dc"},
		{"bridge vpc", str(c.BridgeVPC("vmbr0")), "vpc-04858cd8262694c9d"},
		{"bridge subnet", str(c.BridgeSubnet("vmbr0", "10.0.0.0/24")), "subnet-29f9256c6bad386c4"},
		{"sdn vpc", str(c.SDNVPC("zone1", "vnet1")), "vpc-617f9316b4facaa20"},
		{"sdn subnet", str(c.SDNSubnet("vnet1", "10.1.0.0/24")), "subnet-16447773614414a4d"},
		{"security group", str(c.SecurityGroup("web")), "sg-6fbd3e734140cbd24"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestIDSources(t *testing.T) {
	c := NewIDs("pve-seoul")
	for _, tc := range []struct {
		vm   VM
		want IDSource
	}{
		{VM{UUID: testUUID, VMID: 1, Ctime: "1"}, SourceUUID},
		{VM{VMID: 1, Ctime: "1"}, SourceFallback},
		{VM{VMID: 1}, SourceVMID},
	} {
		if _, got, err := c.Instance(tc.vm); err != nil || got != tc.want {
			t.Fatalf("Instance(%+v) source = %q, %v; want %q", tc.vm, got, err, tc.want)
		}
	}
	if _, src, _ := c.Volume("not a serial", "local-lvm", "vm-1-disk-0"); src != SourceVolname {
		t.Fatalf("foreign serial source = %q, want %q", src, SourceVolname)
	}
	if _, src, _ := c.Volume("64789ba320027f896", "", ""); src != SourceSerial {
		t.Fatalf("serial source = %q, want %q", src, SourceSerial)
	}
}

func TestInstanceIDIgnoresVMID(t *testing.T) {
	c := NewIDs("pve-seoul")
	id := func(vm VM) string {
		got, _, err := c.Instance(vm)
		if err != nil {
			t.Fatal(err)
		}
		return got.String()
	}
	const other = "aaaaaaaa-2222-4333-8444-555555555555"
	if id(VM{UUID: testUUID, VMID: 100}) == id(VM{UUID: other, VMID: 100}) {
		t.Fatal("same VMID, different uuids gave one id")
	}
	if id(VM{UUID: testUUID, VMID: 100}) != id(VM{UUID: testUUID, VMID: 200}) {
		t.Fatal("same uuid, different VMIDs gave two ids")
	}
	if id(VM{UUID: other, VMID: 100}) != "i-7d2f7fa6b5dfcc1ea" {
		t.Fatal("pinned id for the second uuid changed")
	}
}

func TestInputsAreLowerCased(t *testing.T) {
	lower, _, err := NewIDs("pve-seoul").Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	upper, _, err := NewIDs("PVE-Seoul").Instance(VM{UUID: strings.ToUpper(testUUID)})
	if err != nil {
		t.Fatal(err)
	}
	if lower != upper {
		t.Fatalf("%v != %v", lower, upper)
	}
}

func TestInputsAreNULJoined(t *testing.T) {
	var got string
	c := IDs{cluster: "A", hash: func(s string) string { got = s; return sha256Hex(s) }}
	if _, err := c.Snapshot("U", "S"); err != nil {
		t.Fatal(err)
	}
	if want := "vws-pve-snapshot-v1\x00a\x00u\x00s"; got != want {
		t.Fatalf("hash input %q, want %q", got, want)
	}
}

func TestOutputsParseAsSeventeenHex(t *testing.T) {
	id, _, err := NewIDs("pve-seoul").Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := resource.Parse[resource.InstanceID](id.String())
	if err != nil || parsed != id || len(id.String()) != len("i-")+17 {
		t.Fatalf("Parse(%q) = %v, %v", id, parsed, err)
	}
}

func TestMarkCollisionsMarksBothRows(t *testing.T) {
	c := IDs{cluster: "pve-seoul", hash: func(string) string { return strings.Repeat("a", 64) }}
	first, srcA, err := c.Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	second, srcB, err := c.Instance(VM{UUID: "aaaaaaaa-2222-4333-8444-555555555555"})
	if err != nil {
		t.Fatal(err)
	}
	rows := []Row{{first.String(), srcA}, {"i-0000000000000001", SourceUUID}, {second.String(), srcB}}
	MarkCollisions(rows)
	want := []IDSource{SourceCollision, SourceUUID, SourceCollision}
	for i, r := range rows {
		if r.Source != want[i] {
			t.Fatalf("row %d source = %q, want %q", i, r.Source, want[i])
		}
	}
}
