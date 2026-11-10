package proxmox

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const testUUID = "11111111-2222-4333-8444-555555555555"

func newIDs(t *testing.T, cluster string) IDs {
	t.Helper()
	c, err := NewIDs(cluster)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestFormulasArePinned(t *testing.T) {
	c := newIDs(t, "pve-seoul")
	str := func(id fmt.Stringer, err error) string {
		t.Helper()
		return must[fmt.Stringer](t)(id, err).String()
	}
	serial := must[string](t)
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
		{"volume serial", serial(c.VolumeSerial("key1", 0)), "64789ba320027f896"},
		{"root volume serial", serial(c.RootVolumeSerial(testUUID)), "1242e29aa9300a558"},
		{"volume by serial", vol("64789ba320027f896"), "vol-64789ba320027f896"},
		{"volume by upper-case serial", vol("64789BA320027F896"), "vol-64789ba320027f896"},
		{"volume by name", vol(""), "vol-605b08b939ebcfc8e"},
		{"volume with a foreign 17-character serial", vol("64789ba320027f89z"), "vol-605b08b939ebcfc8e"},
		{"volume with a foreign 20-byte serial", vol("QM00001-ABCDEFGHIJK"), "vol-605b08b939ebcfc8e"},
		{"bridge vpc", str(c.BridgeVPC("vmbr0")), "vpc-04858cd8262694c9d"},
		{"bridge subnet", str(c.BridgeSubnet("vmbr0", "10.0.0.0/24")), "subnet-29f9256c6bad386c4"},
		{"sdn vpc", str(c.SDNVPC("zone1", "vnet1")), "vpc-ea91b128a0c0a85ee"},
		{"sdn subnet", str(c.SDNSubnet("vnet1", "10.1.0.0/24")), "subnet-551fa8fab90a9dec9"},
		{"security group", str(c.SecurityGroup("web")), "sg-6fbd3e734140cbd24"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// Two id forms of one kind must never hash the same input: a zone named
// "bridge" once gave its VNet the id of the bridge of the same name.
func TestFormsNeverShareHashInput(t *testing.T) {
	c := newIDs(t, "pve-seoul")
	serial := must[string](t)
	bridgeVPC := must[resource.VpcID](t)(c.BridgeVPC("vmbr0"))
	if sdnVPC := must[resource.VpcID](t)(c.SDNVPC("bridge", "vmbr0")); bridgeVPC == sdnVPC {
		t.Errorf("SDNVPC(bridge, vmbr0) = BridgeVPC(vmbr0) = %v", sdnVPC)
	}
	bridgeSubnet := must[resource.SubnetID](t)(c.BridgeSubnet("vmbr0", "10.0.0.0/24"))
	if sdnSubnet, err := c.SDNSubnet("bridge\x00vmbr0", "10.0.0.0/24"); err == nil && bridgeSubnet == sdnSubnet {
		t.Errorf("SDNSubnet(bridge NUL vmbr0) = BridgeSubnet(vmbr0) = %v", sdnSubnet)
	}
	named, _, err := c.Volume("", testUUID, "root")
	if err != nil {
		t.Fatal(err)
	}
	if root := serial(c.RootVolumeSerial(testUUID)); named.String() == "vol-"+root {
		t.Errorf("Volume(storage %s, volname root) = the root volume %v", testUUID, named)
	}
	named, _, err = c.Volume("", "key1", "0")
	if err != nil {
		t.Fatal(err)
	}
	if created := serial(c.VolumeSerial("key1", 0)); named.String() == "vol-"+created {
		t.Errorf("Volume(storage key1, volname 0) = the created volume %v", named)
	}
}

// Each input no id can be computed from is an error, never a shared id.
func TestBadInputsAreRefused(t *testing.T) {
	c := newIDs(t, "pve-seoul")
	short := IDs{cluster: "c", hash: func(string) string { return "abc" }}
	pair := func(_ any, err error) error { return err }
	triple := func(_ any, _ IDSource, err error) error { return err }
	for _, tc := range []struct {
		name  string
		err   error
		input bool
	}{
		{"empty cluster", pair(NewIDs("")), true},
		{"NUL in the cluster", pair(NewIDs("pve\x00seoul")), true},
		{"IDs not made by NewIDs", pair(IDs{}.Reservation("key1")), true},
		{"a hash shorter than 17 digits", pair(short.Reservation("key1")), false},
		{"malformed uuid", triple(c.Instance(VM{UUID: "not-a-uuid", VMID: 100})), true},
		{"all-zero uuid", triple(c.Instance(VM{UUID: "00000000-0000-0000-0000-000000000000"})), true},
		{"ctime that is not decimal", triple(c.Instance(VM{VMID: 100, Ctime: "nometa"})), true},
		{"ctime with a leading zero", triple(c.Instance(VM{VMID: 100, Ctime: "01700000000"})), true},
		{"no uuid and no VMID", triple(c.Instance(VM{})), true},
		{"image without a uuid", pair(c.Image("")), true},
		{"image named like the unknown image", pair(c.Image("unknown")), true},
		{"snapshot without a uuid", pair(c.Snapshot("", "before-upgrade")), true},
		{"snapshot without a name", pair(c.Snapshot(testUUID, "")), true},
		{"empty reservation key", pair(c.Reservation("")), true},
		{"negative volume index", pair(c.VolumeSerial("key1", -1)), true},
		{"root volume without a uuid", pair(c.RootVolumeSerial("")), true},
		{"volume without storage or volname", triple(c.Volume("", "", "")), true},
		{"empty bridge", pair(c.BridgeVPC("")), true},
		{"empty cidr", pair(c.BridgeSubnet("vmbr0", "")), true},
		{"empty SDN zone", pair(c.SDNVPC("", "vnet1")), true},
		{"NUL in a VNet", pair(c.SDNSubnet("vnet1\x00x", "10.0.0.0/24")), true},
		{"empty security group", pair(c.SecurityGroup("")), true},
	} {
		switch {
		case tc.err == nil:
			t.Errorf("%s: no error", tc.name)
		case errors.Is(tc.err, ErrInput) != tc.input:
			t.Errorf("%s: errors.Is(%v, ErrInput) = %t, want %t", tc.name, tc.err, !tc.input, tc.input)
		}
	}
}

func TestIDSources(t *testing.T) {
	c := newIDs(t, "pve-seoul")
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
	c := newIDs(t, "pve-seoul")
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

func TestClusterIsAnInput(t *testing.T) {
	seoul, _, err := newIDs(t, "pve-seoul").Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	busan, _, err := newIDs(t, "pve-busan").Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	if seoul == busan {
		t.Fatalf("one uuid in two clusters gave one id %v", seoul)
	}
}

func TestInputsAreLowerCased(t *testing.T) {
	lower, _, err := newIDs(t, "pve-seoul").Instance(VM{UUID: testUUID})
	if err != nil {
		t.Fatal(err)
	}
	upper, _, err := newIDs(t, "PVE-Seoul").Instance(VM{UUID: strings.ToUpper(testUUID)})
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
	if _, err := c.Snapshot(strings.ToUpper(testUUID), "S"); err != nil {
		t.Fatal(err)
	}
	if want := "vws-pve-snapshot-v1\x00a\x00" + testUUID + "\x00s"; got != want {
		t.Fatalf("hash input %q, want %q", got, want)
	}
}

func TestOutputsParseAsSeventeenHex(t *testing.T) {
	id, _, err := newIDs(t, "pve-seoul").Instance(VM{UUID: testUUID})
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
	third, srcC, err := c.Instance(VM{VMID: 100})
	if err != nil {
		t.Fatal(err)
	}
	unique := must[resource.InstanceID](t)(resource.Parse[resource.InstanceID]("i-0000000000000001"))
	vpc := must[resource.VpcID](t)(c.BridgeVPC("vmbr0"))
	rows := []Row{
		{first.Ref(), srcA}, {unique.Ref(), SourceUUID}, {second.Ref(), srcB}, {third.Ref(), srcC}, {vpc.Ref(), ""},
	}
	MarkCollisions(rows)
	MarkCollisions(nil)
	want := []IDSource{SourceCollision, SourceUUID, SourceCollision, SourceCollision, ""}
	for i, r := range rows {
		if r.Source != want[i] {
			t.Fatalf("row %d source = %q, want %q", i, r.Source, want[i])
		}
	}
}
