package proxmox

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func pveTagPattern() *regexp.Regexp {
	return regexp.MustCompile(`^[a-z0-9_][a-z0-9_\-\+\.]*$`)
}

func TestEncodePinsTheDesignExamples(t *testing.T) {
	for _, c := range []struct{ key, value, want string }{
		{"Name", "web-01", "vws.t.+name.web-01"},
		{"cost:center", "R&D \uD300", "vws.t.cost_3acenter.+r_26+d_20_ed_8c_80"},
		{"env", "", "vws.t.env."},
		{"a.b_c+d", "x", "vws.t.a_2eb_5fc_2bd.x"},
	} {
		got, err := EncodeTag(c.key, c.value)
		if err != nil || got != c.want {
			t.Fatalf("EncodeTag(%q, %q) = %q, %v; want %q", c.key, c.value, got, err, c.want)
		}
		k, v, ok := DecodeTag(got)
		if !ok || k != c.key || v != c.value {
			t.Fatalf("DecodeTag(%q) = %q, %q, %v", got, k, v, ok)
		}
	}
}

func FuzzTagRoundTrip(f *testing.F) {
	f.Add("Name", "web-01")
	f.Add("cost:center", "R&D \uD300")
	f.Add("", "")
	f.Add("a+b_c.d", "\xff\x00Z")
	re := pveTagPattern()
	f.Fuzz(func(t *testing.T, key, value string) {
		tag, err := EncodeTag(key, value)
		if err != nil {
			if !reservedKey(key) {
				t.Fatalf("EncodeTag(%q, %q) failed: %v", key, value, err)
			}
			return
		}
		if !re.MatchString(tag) {
			t.Fatalf("EncodeTag(%q, %q) = %q does not match the Proxmox tag pattern", key, value, tag)
		}
		k, v, ok := DecodeTag(tag)
		if !ok || k != key || v != value {
			t.Fatalf("DecodeTag(%q) = %q, %q, %v; want %q, %q", tag, k, v, ok, key, value)
		}
	})
}

func TestReservedKeysAreInvalidParameterValue(t *testing.T) {
	for _, key := range []string{"aws:x", "AWS:x", "vws:x", "vws.x", "VWS.t.y"} {
		_, err := EncodeTag(key, "v")
		if e := resource.AsError(err); e == nil || e.Code != resource.CodeInvalidArgument {
			t.Fatalf("EncodeTag(%q) = %v; want InvalidArgument", key, err)
		}
		if _, _, err := Split(map[string]string{key: "v"}); err == nil {
			t.Fatalf("Split accepted %q", key)
		}
	}
}

func TestDecodeRefusesWhatEncodeNeverWrites(t *testing.T) {
	for _, tag := range []string{
		"web", "vws.t.", "vws.t.a", "vws.t.A.b", "vws.t.+.b", "vws.t._4.b", "vws.t._4F.b", "vws.t.a.b.c", "vws.t.a..b",
		"vws.t.a b.c",
	} {
		if k, v, ok := DecodeTag(tag); ok {
			t.Fatalf("DecodeTag(%q) = %q, %q", tag, k, v)
		}
	}
}

func TestLongTagMovesToTheDescriptionAndMergesOnce(t *testing.T) {
	long := strings.Repeat("é", 100)
	tags := map[string]string{"Name": "web", "long": long}
	pve, overflow, err := Split(tags)
	if err != nil {
		t.Fatal(err)
	}
	wantOverflow := map[string]string{"long": long}
	if !reflect.DeepEqual(pve, []string{"vws.t.+name.web"}) || !reflect.DeepEqual(overflow, wantOverflow) {
		t.Fatalf("Split = %v, %v", pve, overflow)
	}
	desc, err := WithDescriptionTags("my vm\n", overflow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(desc, "my vm\nvws:tags ") {
		t.Fatalf("description = %q", desc)
	}
	got, err := ReadTags(pve, desc)
	if err != nil || !reflect.DeepEqual(got.User, tags) {
		t.Fatalf("ReadTags = %v, %v; want %v", got.User, err, tags)
	}

	again, err := WithDescriptionTags(desc, map[string]string{"long": long, "Name": "stale"})
	if err != nil || strings.Count(again, "vws:tags ") != 1 || !strings.HasPrefix(again, "my vm\n") {
		t.Fatalf("WithDescriptionTags replaced badly: %q, %v", again, err)
	}
	got, err = ReadTags(pve, again)
	if err != nil || !reflect.DeepEqual(got.User, tags) {
		t.Fatalf("a key in both sources: ReadTags = %v, %v; want the Proxmox tag to win", got.User, err)
	}

	cleared, err := WithDescriptionTags(again, nil)
	if err != nil || cleared != "my vm" {
		t.Fatalf("clearing the block left %q, %v", cleared, err)
	}
}

func TestBadDescriptionBlockIsAnError(t *testing.T) {
	if _, err := ReadTags(nil, "vws:tags {nope"); err == nil {
		t.Fatal("ReadTags accepted a broken block")
	}
}

func TestSystemTagsAreNeverUserTags(t *testing.T) {
	system := []string{
		"vws.k.abc", "vws.f.abc", "vws.n.0", "vws.r.0123456789abcdef0", "vws.ami.0123456789abcdef0", "vws.kp.key",
		"vws.dot.00000001", "vws.d.k.f.1", "vws.vt.12345678.+a.b", "vws.holder", "vws.live.run1",
	}
	user, _ := EncodeTag("Name", "web")
	got, err := ReadTags(append(slices.Clone(system), user, "prod"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.System, system) || !reflect.DeepEqual(got.User, map[string]string{"Name": "web"}) {
		t.Fatalf("ReadTags = %+v", got)
	}
}
