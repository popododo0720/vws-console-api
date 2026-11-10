package proxmox

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

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
	f.Add("a+b_c.d", "\x00Z")
	re := pveTagPattern()
	f.Fuzz(func(t *testing.T, key, value string) {
		tag, err := EncodeTag(key, value)
		valid := key != "" && !reservedKey(key) && utf8.ValidString(key) && utf8.ValidString(value)
		if err != nil {
			if valid {
				t.Fatalf("EncodeTag(%q, %q) failed: %v", key, value, err)
			}
			return
		}
		if !valid {
			t.Fatalf("EncodeTag(%q, %q) = %q; want an error", key, value, tag)
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

// Whatever DecodeTag accepts is exactly what EncodeTag writes, so two Proxmox
// tags never decode to one key (rev-1 and rev-2 finding 1).
func FuzzDecodeIsCanonical(f *testing.F) {
	for _, tag := range []string{
		"vws.t.+a.b", "vws.t._41.b", "vws.t._61.b", "vws.t.a._ff", "vws.t..x", "vws.t.aws_3ax.y",
	} {
		f.Add(tag)
	}
	f.Fuzz(func(t *testing.T, tag string) {
		k, v, ok := DecodeTag(tag)
		if !ok {
			return
		}
		if got, err := EncodeTag(k, v); err != nil || got != tag {
			t.Fatalf("DecodeTag(%q) = %q, %q but EncodeTag gives %q, %v", tag, k, v, got, err)
		}
	})
}

func TestReservedKeysAreInvalidParameterValue(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"aws:x", "v"},
		{"AWS:x", "v"},
		{"vws:x", "v"},
		{"vws.x", "v"},
		{"VWS.t.y", "v"},
		{"", "v"},
		{"\xff", "v"},
		{"k", "\xff"},
	} {
		key := c.key
		_, err := EncodeTag(key, c.value)
		if e := resource.AsError(err); e == nil || e.Code != resource.CodeInvalidArgument {
			t.Fatalf("EncodeTag(%q, %q) = %v; want InvalidArgument", key, c.value, err)
		}
		if _, _, err := Split(map[string]string{key: c.value}); err == nil {
			t.Fatalf("Split accepted %q", key)
		}
	}
}

func TestDecodeRefusesWhatEncodeNeverWrites(t *testing.T) {
	for _, tag := range []string{
		"web", "vws.t.", "vws.t.a", "vws.t.A.b", "vws.t.+.b", "vws.t._4.b", "vws.t._4F.b", "vws.t.a.b.c", "vws.t.a..b",
		"vws.t.a b.c",
		// Escapes EncodeTag never writes: a byte with a plain form, an empty key,
		// invalid UTF-8 and reserved keys.
		"vws.t._61.b", "vws.t._41.b", "vws.t._2d.b", "vws.t._30.b", "vws.t.a._61", "vws.t..x", "vws.t.a._ff",
		"vws.t.aws_3ax.y", "vws.t.vws_2ex.y", "vws.t.+v+w+s_2ek.x",
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
	for _, desc := range []string{"vws:tags {nope", "vws:tags {\"a\":1}", "vws:tags {}\nvws:tags {\"a\":\"b\"}"} {
		if _, err := ReadTags(nil, desc); err == nil {
			t.Fatalf("ReadTags accepted the description %q", desc)
		}
	}
}

// Only a "vws:tags {" line is the block: other text an operator writes, a JSON
// null included, is description text and never fails or panics the read.
func TestOnlyAJSONObjectLineIsTheBlock(t *testing.T) {
	for _, desc := range []string{
		"vws:tags null", "vws:tags []", `vws:tags "x"`, "vws:tags are listed below\nmore", "vws:tags", "vws:tags {}",
	} {
		got, err := ReadTags([]string{"vws.t.a.b"}, desc)
		if err != nil || !reflect.DeepEqual(got.User, map[string]string{"a": "b"}) {
			t.Fatalf("ReadTags(%q) = %v, %v", desc, got.User, err)
		}
	}
	got, err := ReadTags(nil, "note\r\nvws:tags {\"k\":\"v\"}\r\n")
	if err != nil || !reflect.DeepEqual(got.User, map[string]string{"k": "v"}) {
		t.Fatalf("a CRLF block: ReadTags = %v, %v", got.User, err)
	}
}

func TestReservedKeysAreNeverReadAsUserTags(t *testing.T) {
	got, err := ReadTags([]string{"vws.t.aws_3ax.y"}, `vws:tags {"aws:x":"1","vws.k.x":"2","VWS:y":"3","":"4","ok":"5"}`)
	if err != nil || !reflect.DeepEqual(got.User, map[string]string{"ok": "5"}) {
		t.Fatalf("ReadTags = %v, %v; want only ok=5", got.User, err)
	}
}

// Two canonical tags with one key (a hand edit) give the same answer in any
// stored order.
func TestDuplicateKeyDoesNotDependOnOrder(t *testing.T) {
	for _, pve := range [][]string{{"vws.t.a.2", "vws.t.a.1"}, {"vws.t.a.1", "vws.t.a.2"}} {
		got, err := ReadTags(pve, "")
		if err != nil || !reflect.DeepEqual(got.User, map[string]string{"a": "1"}) {
			t.Fatalf("ReadTags(%q) = %v, %v; want a=1", pve, got.User, err)
		}
	}
}

func TestSystemTagsAreNeverUserTags(t *testing.T) {
	system := []string{
		"vws.k.abc", "vws.f.abc", "vws.n.0", "vws.r.0123456789abcdef0", "vws.ami.0123456789abcdef0", "vws.kp.key",
		"vws.dot.00000001", "vws.d.k.f.1", "vws.vt.12345678.+a.b", "vws.holder", "vws.live.run1",
		"VWS.holder", "vws.later.1",
	}
	user, err := EncodeTag("Name", "web")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadTags(append(slices.Clone(system), user, "prod"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.System, system) || !reflect.DeepEqual(got.User, map[string]string{"Name": "web"}) ||
		!reflect.DeepEqual(got.Other, []string{"prod"}) {
		t.Fatalf("ReadTags = %+v", got)
	}
}

// A tag that is neither a user tag nor a system tag is kept as stored, so a
// writer never deletes an operator's tag or one it cannot decode.
func TestTagsThatDoNotDecodeAreKept(t *testing.T) {
	other := []string{"prod", "vws.t.x", "VWS.T.+NAME.X", "vws.t._61.b"}
	got, err := ReadTags(append(slices.Clone(other), "vws.k.1"), "")
	if err != nil || len(got.User) != 0 || !reflect.DeepEqual(got.Other, other) ||
		!reflect.DeepEqual(got.System, []string{"vws.k.1"}) {
		t.Fatalf("ReadTags = %+v, %v", got, err)
	}
}
