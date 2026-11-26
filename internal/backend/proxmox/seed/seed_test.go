package seed

import (
	"bytes"
	"encoding/binary"
	"flag"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

var update = flag.Bool("update", false, "rewrite testdata/*.iso from the current writer")

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEC8lf7xuF2l"

func static() *Static {
	mac, err := net.ParseMAC("BC:24:11:5E:7A:01")
	if err != nil {
		panic(err)
	}
	return &Static{
		MAC:         mac,
		Address:     netip.MustParsePrefix("10.0.0.5/24"),
		Gateway:     netip.MustParseAddr("10.0.0.1"),
		Nameservers: []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")},
	}
}

func staticSeed() Seed {
	return Seed{
		InstanceID: "i-0a1b2c3d4e5f60718",
		PublicKey:  testKey,
		Network:    static(),
		UserData:   []byte("#cloud-config\npackages:\n- nginx\n"),
	}
}

func dhcpSeed() Seed { return Seed{InstanceID: "i-0a1b2c3d4e5f60718"} }

func mustISO(t *testing.T, s Seed) []byte {
	t.Helper()
	img, err := s.ISO()
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// The files are the fixed templates, the network-config text the one PVE
// writes for the same NIC.
func TestFiles(t *testing.T) {
	files, err := staticSeed().files()
	if err != nil {
		t.Fatal(err)
	}
	want := []file{
		{"meta-data", []byte("instance-id: i-0a1b2c3d4e5f60718\nlocal-hostname: i-0a1b2c3d4e5f60718\n" +
			"public-keys:\n- '" + testKey + "'\n")},
		{"network-config", []byte(`version: 1
config:
    - type: physical
      name: eth0
      mac_address: 'bc:24:11:5e:7a:01'
      subnets:
      - type: static
        address: '10.0.0.5'
        netmask: '255.255.255.0'
        gateway: '10.0.0.1'
    - type: nameserver
      address:
      - '10.0.0.2'
      - '10.0.0.3'
`)},
		{"user-data", []byte("#cloud-config\npackages:\n- nginx\n")},
	}
	checkFiles(t, files, want)

	// DHCP and no key: no network-config, no public-keys, an empty user-data.
	files, err = dhcpSeed().files()
	if err != nil {
		t.Fatal(err)
	}
	checkFiles(t, files, []file{
		{"meta-data", []byte("instance-id: i-0a1b2c3d4e5f60718\nlocal-hostname: i-0a1b2c3d4e5f60718\n")},
		{"user-data", nil},
	})
}

func checkFiles(t *testing.T, got, want []file) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].name != want[i].name || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("file %d: got %s %q, want %s %q", i, got[i].name, got[i].data, want[i].name, want[i].data)
		}
	}
}

// One fixed Seed per layout equals a committed image byte for byte.
func TestGolden(t *testing.T) {
	for name, s := range map[string]Seed{"static.iso": staticSeed(), "dhcp.iso": dhcpSeed()} {
		path := filepath.Join("testdata", name)
		img := mustISO(t, s)
		if *update {
			if err := os.WriteFile(path, img, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(img, want) {
			t.Errorf("%s drifted from the golden image; rerun with -update only for an intended change", name)
		}
	}
}

func TestSameSeedSameBytes(t *testing.T) {
	a, b := mustISO(t, staticSeed()), mustISO(t, staticSeed())
	if !bytes.Equal(a, b) {
		t.Fatal("two images of one Seed differ")
	}
	other := staticSeed()
	other.UserData = []byte("#cloud-config\npackages:\n- nginz\n")
	if bytes.Equal(a, mustISO(t, other)) {
		t.Fatal("different user data gave the same image")
	}
}

// entry is a directory record as the test reads it.
type entry struct {
	name         string
	extent, size uint32
}

// Every both-endian field agrees, every extent is inside the image, and each
// file's bytes are at its extent in both trees, at user data sizes around
// the sector size.
func TestStructure(t *testing.T) {
	for _, size := range []int{0, 1, 2047, 2048, 2049, 16384, MaxUserData} {
		s := staticSeed()
		s.UserData = bytes.Repeat([]byte{'u'}, size)
		files, err := s.files()
		if err != nil {
			t.Fatal(err)
		}
		img := mustISO(t, s)
		sectors := uint32(firstExtent)
		for _, f := range files {
			sectors += uint32((len(f.data) + sectorSize - 1) / sectorSize)
		}
		if len(img) != int(sectors)*sectorSize {
			t.Fatalf("size %d: image is %d bytes, want %d sectors", size, len(img), sectors)
		}
		sector := func(n int) []byte { return img[n*sectorSize : (n+1)*sectorSize] }
		for n, kind := range map[int]byte{16: 1, 17: 2, 18: 255} {
			if d := sector(n); d[0] != kind || string(d[1:7]) != "CD001\x01" {
				t.Fatalf("size %d: sector %d is not volume descriptor %d", size, n, kind)
			}
		}
		for _, n := range []int{16, 17} {
			d := sector(n)
			for _, off := range []int{80, 132} {
				if both32At(t, d, off) == 0 {
					t.Fatalf("size %d: descriptor %d field %d is 0", size, n, off)
				}
			}
			for off, want := range map[int]uint16{120: 1, 124: 1, 128: sectorSize} {
				if got := both16At(t, d, off); got != want {
					t.Fatalf("size %d: descriptor %d field %d = %d, want %d", size, n, off, got, want)
				}
			}
			if both32At(t, d, 80) != sectors {
				t.Fatalf("size %d: descriptor %d volume size differs from the image", size, n)
			}
			l, m := binary.LittleEndian.Uint32(d[140:]), binary.BigEndian.Uint32(d[148:])
			root := both32At(t, d[156:], 2)
			for _, table := range []struct {
				at    uint32
				order binary.ByteOrder
			}{{l, binary.LittleEndian}, {m, binary.BigEndian}} {
				p := sector(int(table.at))
				if p[0] != 1 || table.order.Uint32(p[2:]) != root || table.order.Uint16(p[6:]) != 1 {
					t.Fatalf("size %d: descriptor %d path table at %d does not name root %d", size, n, table.at, root)
				}
			}
			joliet := n == 17
			if joliet != (string(d[88:91]) == "%/E") {
				t.Fatalf("size %d: descriptor %d Joliet escape %q", size, n, d[88:91])
			}
			label := string(d[40:72])
			if joliet {
				label = fromUCS2(d[40:72])
			}
			if strings.TrimRight(label, " ") != "cidata" {
				t.Fatalf("size %d: descriptor %d label %q", size, n, label)
			}
			entries := readRoot(t, img, root, joliet)
			if len(entries) != len(files) {
				t.Fatalf("size %d: descriptor %d root has %d files, want %d", size, n, len(entries), len(files))
			}
			for i, f := range files {
				want := strings.ToUpper(strings.ReplaceAll(f.name, "-", "_")) + ".;1"
				if joliet {
					want = f.name + ";1"
				}
				e := entries[i]
				if e.name != want || e.size != uint32(len(f.data)) {
					t.Fatalf("size %d: entry %d is %q of %d bytes, want %q of %d", size, i, e.name, e.size, want, len(f.data))
				}
				end := int(e.extent)*sectorSize + int(e.size)
				if e.size > 0 && (e.extent < firstExtent || end > len(img)) {
					t.Fatalf("size %d: %s extent %d is outside the image", size, e.name, e.extent)
				}
				if !bytes.Equal(img[int(e.extent)*sectorSize:end], f.data) {
					t.Fatalf("size %d: %s bytes differ at its extent", size, e.name)
				}
			}
		}
	}
}

func readRoot(t *testing.T, img []byte, root uint32, joliet bool) []entry {
	t.Helper()
	dir := img[int(root)*sectorSize : int(root+1)*sectorSize]
	var out []entry
	for i := 0; dir[0] != 0; i++ {
		n := int(dir[0])
		r := dir[:n]
		e := entry{extent: both32At(t, r, 2), size: both32At(t, r, 10)}
		if both16At(t, r, 28) != 1 || n != 33+int(r[32])+(33+int(r[32]))%2 {
			t.Fatalf("record %d is malformed", i)
		}
		id := r[33 : 33+int(r[32])]
		e.name = string(id)
		if joliet && i > 1 {
			e.name = fromUCS2(id)
		}
		if i < 2 {
			if r[25] != 2 || e.extent != root || len(id) != 1 || id[0] != byte(i) {
				t.Fatalf("record %d is not . or ..", i)
			}
		} else {
			out = append(out, e)
		}
		dir = dir[n:]
	}
	return out
}

func both32At(t *testing.T, b []byte, off int) uint32 {
	t.Helper()
	le, be := binary.LittleEndian.Uint32(b[off:]), binary.BigEndian.Uint32(b[off+4:])
	if le != be {
		t.Fatalf("both-endian field at %d: %d and %d", off, le, be)
	}
	return le
}

func both16At(t *testing.T, b []byte, off int) uint16 {
	t.Helper()
	le, be := binary.LittleEndian.Uint16(b[off:]), binary.BigEndian.Uint16(b[off+2:])
	if le != be {
		t.Fatalf("both-endian field at %d: %d and %d", off, le, be)
	}
	return le
}

func fromUCS2(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func TestRefusals(t *testing.T) {
	for name, edit := range map[string]func(*Seed){
		"short instance id":     func(s *Seed) { s.InstanceID = "i-0a1b2c3d4e5f6071" },
		"upper-case instance":   func(s *Seed) { s.InstanceID = "i-0A1B2C3D4E5F60718" },
		"key without algorithm": func(s *Seed) { s.PublicKey = "AAAAC3NzaC1lZDI1NTE5" },
		"key with a comment":    func(s *Seed) { s.PublicKey = testKey + " me@host" },
		"key with a quote":      func(s *Seed) { s.PublicKey = "ssh-ed25519 AAAA'AAAA" },
		"key not base64":        func(s *Seed) { s.PublicKey = "ssh-ed25519 AAAAA" },
		"key with a newline":    func(s *Seed) { s.PublicKey = testKey + "\n" },
		"MAC of 8 bytes":        func(s *Seed) { s.Network.MAC = net.HardwareAddr{1, 2, 3, 4, 5, 6, 7, 8} },
		"no address":            func(s *Seed) { s.Network.Address = netip.Prefix{} },
		"IPv6 address":          func(s *Seed) { s.Network.Address = netip.MustParsePrefix("fd00::5/64") },
		"no gateway":            func(s *Seed) { s.Network.Gateway = netip.Addr{} },
		"IPv6 gateway":          func(s *Seed) { s.Network.Gateway = netip.MustParseAddr("fd00::1") },
		"no nameserver":         func(s *Seed) { s.Network.Nameservers = nil },
		"four nameservers": func(s *Seed) {
			s.Network.Nameservers = append(s.Network.Nameservers, s.Network.Nameservers...)
		},
		"IPv6 nameserver":   func(s *Seed) { s.Network.Nameservers[1] = netip.MustParseAddr("fd00::2") },
		"mapped nameserver": func(s *Seed) { s.Network.Nameservers[0] = netip.MustParseAddr("::ffff:10.0.0.2") },
		"user data too big": func(s *Seed) { s.UserData = bytes.Repeat([]byte{'u'}, MaxUserData+1) },
	} {
		t.Run(name, func(t *testing.T) {
			s := staticSeed()
			edit(&s)
			img, err := s.ISO()
			if err == nil || img != nil {
				t.Fatalf("accepted: %d bytes", len(img))
			}
			if strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "uuu") {
				t.Fatalf("the error carries the key or user data: %v", err)
			}
		})
	}
	// The limits themselves are accepted.
	s := staticSeed()
	s.UserData = bytes.Repeat([]byte{'u'}, MaxUserData)
	s.Network.Nameservers = append(s.Network.Nameservers, netip.MustParseAddr("10.0.0.4"))
	mustISO(t, s)
}

// External readers, each independent of this package, read the image: the
// tools CI installs. Without CI a missing tool skips its check; with CI it
// fails.
func TestExternalReaders(t *testing.T) {
	for name, s := range map[string]Seed{"static": staticSeed(), "dhcp": dhcpSeed()} {
		t.Run(name, func(t *testing.T) {
			files, err := s.files()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			iso := filepath.Join(dir, "seed.iso")
			if err := os.WriteFile(iso, mustISO(t, s), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Run("isoinfo", func(t *testing.T) {
				tool(t, "isoinfo")
				list := run(t, "isoinfo", "-J", "-l", "-i", iso)
				for _, f := range files {
					if !bytes.Contains(list, []byte(" "+f.name+";1")) {
						t.Errorf("isoinfo -J -l lists no %s:\n%s", f.name, list)
					}
					if got := run(t, "isoinfo", "-J", "-x", "/"+f.name+";1", "-i", iso); !bytes.Equal(got, f.data) {
						t.Errorf("isoinfo -J -x %s: %q, want %q", f.name, got, f.data)
					}
				}
			})
			t.Run("bsdtar", func(t *testing.T) {
				tool(t, "bsdtar")
				out := t.TempDir()
				run(t, "bsdtar", "-xf", iso, "-C", out)
				entries, err := os.ReadDir(out)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != len(files) {
					t.Errorf("bsdtar extracted %d files, want %d", len(entries), len(files))
				}
				for _, f := range files {
					got, err := os.ReadFile(filepath.Join(out, f.name))
					if err != nil || !bytes.Equal(got, f.data) {
						t.Errorf("bsdtar %s: %q %v, want %q", f.name, got, err, f.data)
					}
				}
			})
			t.Run("blkid", func(t *testing.T) {
				tool(t, "blkid")
				if got := strings.TrimSpace(string(run(t, "blkid", "-p", "-o", "value", "-s", "LABEL", iso))); got != "cidata" {
					t.Errorf("blkid label %q, want cidata", got)
				}
				if got := strings.TrimSpace(string(run(t, "blkid", "-p", "-o", "value", "-s", "TYPE", iso))); got != "iso9660" {
					t.Errorf("blkid type %q, want iso9660", got)
				}
			})
			t.Run("qemu-img", func(t *testing.T) {
				tool(t, "qemu-img")
				if info := run(t, "qemu-img", "info", "--output=json", iso); !bytes.Contains(info, []byte(`"format": "raw"`)) {
					t.Errorf("qemu-img info:\n%s", info)
				}
			})
		})
	}
}

// tool skips the test without the tool, or fails it under CI.
func tool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not installed; CI must install it", name)
		}
		t.Skipf("%s is not installed", name)
	}
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.Bytes())
	}
	return out
}
