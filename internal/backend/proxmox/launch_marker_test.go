package proxmox

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func launchMarker(t *testing.T) LaunchMarker {
	t.Helper()
	image, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	subnet, err := resource.Parse[resource.SubnetID]("subnet-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	return LaunchMarker{
		UUID: "5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10",
		Key:  strings.Repeat("a", 64), Fingerprint: strings.Repeat("f", 64),
		Index: 0, Count: 1, Image: image, Account: inventoryScope().Account,
		Type: "vws.small", Subnet: subnet, KeyPair: "team key",
		Snippet: "local:snippets/launch.yaml", DOT: []string{"01234567"}, Attempt: 1,
	}
}

func TestLaunchMarkerGoldenAndTags(t *testing.T) {
	m := launchMarker(t)
	want := "vws:v=1 uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10 key=" + strings.Repeat("a", 64) +
		" fp=" + strings.Repeat("f", 64) + " n=0/1 ami=ami-0123456789abcdef0 acct=123456789012" +
		" type=vws.small subnet=subnet-0123456789abcdef0 kp=team+key" +
		" ud=local%3Asnippets%2Flaunch.yaml dot=01234567 attempt=1"
	got, err := WithLaunchMarker("", m)
	if err != nil || got != want {
		t.Fatalf("marker %q: %v", got, err)
	}
	decoded, found, err := ReadLaunchMarker(got)
	if err != nil || !found || !reflect.DeepEqual(decoded, m) {
		t.Fatalf("decoded %+v, found %v: %v", decoded, found, err)
	}
	reservation, _ := resource.Parse[resource.ReservationID]("r-0123456789abcdef0")
	tags, err := LaunchMarkerTags(m, reservation)
	wantTags := []string{
		"vws.k." + strings.Repeat("a", 24), "vws.f." + strings.Repeat("f", 16),
		"vws.n.0", "vws.r.0123456789abcdef0",
	}
	if err != nil || !reflect.DeepEqual(tags, wantTags) {
		t.Fatalf("tags %v: %v", tags, err)
	}
	for _, tag := range tags {
		if !pveTagPattern().MatchString(tag) {
			t.Fatalf("invalid PVE tag %q", tag)
		}
	}
	if _, err := LaunchMarkerTags(m, resource.ReservationID{}); err == nil {
		t.Fatal("empty reservation accepted")
	}
}

func TestLaunchMarkerPreservesDescriptionAndBudget(t *testing.T) {
	m := launchMarker(t)
	text := "operator notes\r\nvws:tags {\"long\":\"value\"}\n"
	first, err := WithLaunchMarker(text, m)
	if err != nil || !strings.HasPrefix(first, text) {
		t.Fatalf("description changed: %q: %v", first, err)
	}
	again, err := WithLaunchMarker(first, m)
	if err != nil || again != first {
		t.Fatalf("retry changed description: %q: %v", again, err)
	}
	m.Attempt++
	changed, err := WithLaunchMarker(first, m)
	if err != nil || !strings.HasPrefix(changed, text) {
		t.Fatalf("replacement changed operator text: %q: %v", changed, err)
	}
	line, _ := m.line()
	padding := strings.Repeat("x", MaxDescriptionBytes-len(line)-1)
	exact, err := WithLaunchMarker(padding, m)
	if err != nil || len(exact) != MaxDescriptionBytes {
		t.Fatalf("boundary length %d: %v", len(exact), err)
	}
	if _, err := WithLaunchMarker(padding+"x", m); !errors.Is(err, ErrInput) {
		t.Fatalf("over budget accepted: %v", err)
	}
	if _, found, err := ReadLaunchMarker(text); found || err != nil {
		t.Fatalf("operator text became marker: %v: %v", found, err)
	}
}

func TestLaunchMarkerLargestRequestFitsDescription(t *testing.T) {
	m := launchMarker(t)
	req := resource.RunInstancesRequest{
		ImageID: m.Image, SubnetID: m.Subnet, InstanceType: "vws.xlarge", Count: 10,
		KeyName: strings.Repeat("+", 255), UserData: strings.Repeat("s", resource.MaxUserDataBytes),
		Tags: map[string]string{},
	}
	for i := range 50 {
		req.Tags[fmt.Sprintf("%03d", i)+strings.Repeat("k", 125)] = strings.Repeat("v", 256)
	}
	for i := range resource.MaxLaunchVolumes - 1 {
		req.ExtraVolumes = append(req.ExtraVolumes, resource.LaunchVolume{
			Device: fmt.Sprintf("/dev/sd%c", 'a'+i), SizeGiB: 1,
		})
	}
	req, err := req.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	m.Count, m.KeyPair, m.Type = req.Count, req.KeyName, req.InstanceType
	m.Snippet = "local:snippets/" + strings.Repeat("s", 1024-len("local:snippets/"))
	m.DOT = nil
	for i := range resource.MaxLaunchVolumes {
		m.DOT = append(m.DOT, fmt.Sprintf("%08x", i))
	}
	m.Attempt = int(^uint(0) >> 1)
	for i := range req.Count {
		m.Index = i
		description, err := WithLaunchMarker("", m)
		if err != nil || len(description) >= MaxDescriptionBytes {
			t.Fatalf("instance %d: length %d: %v", i, len(description), err)
		}
		if strings.Contains(description, req.UserData) {
			t.Fatal("user-data body leaked into description")
		}
		got, found, err := ReadLaunchMarker(description)
		if err != nil || !found || !reflect.DeepEqual(got, m) {
			t.Fatalf("largest marker round trip: %+v: %v", got, err)
		}
	}
	overflow, err := WithDescriptionTags("", req.Tags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithLaunchMarker(overflow, m); err == nil {
		t.Fatal("oversized user tag block bypassed complete description budget")
	}
}

func TestLaunchMarkerUserDataIsOnlyASnippetPath(t *testing.T) {
	m := launchMarker(t)
	for _, body := range []string{"#cloud-config\npassword: secret", strings.Repeat("x", resource.MaxUserDataBytes)} {
		m.Snippet = body
		if _, err := WithLaunchMarker("", m); !errors.Is(err, ErrInput) {
			t.Fatalf("user-data body accepted: %v", err)
		}
	}
	m.Snippet = "local:snippets/launch.yaml"
	description, err := WithLaunchMarker("", m)
	if err != nil || !strings.Contains(description, "ud="+url.QueryEscape(m.Snippet)) {
		t.Fatalf("snippet missing: %q: %v", description, err)
	}
	for _, invalid := range []string{
		"/etc/passwd", "local:snippets/../secret", "local:snippets/.", "local:snippets/..",
		"local:snippets/a/b", "local:snippets/a\nfp=bad", "local:snippets/", "local:images/disk",
	} {
		m.Snippet = invalid
		if _, err := WithLaunchMarker("", m); err == nil {
			t.Fatalf("invalid snippet %q accepted", invalid)
		}
	}
}

func TestLaunchMarkerRefusesMalformedRecords(t *testing.T) {
	m := launchMarker(t)
	line, _ := m.line()
	for _, bad := range []string{
		line + " key=" + m.Key, line + "\n" + line, line + " unknown=1",
		strings.Replace(line, "vws:v=1", "vws:v=2", 1),
		strings.Replace(line, "n=0/1", "n=1/1", 1),
		strings.Replace(line, "n=0/1", "n=00/1", 1),
		strings.Replace(line, "n=0/1", "n=0/11", 1),
		strings.Replace(line, "attempt=1", "attempt=0", 1),
		strings.Replace(line, "fp="+m.Fingerprint, "fp=short", 1),
		strings.Replace(line, "kp=team+key", "kp=%zz", 1),
		strings.Replace(line, "dot=01234567", "dot=01234567,01234567", 1),
		strings.TrimSuffix(line, " attempt=1"), strings.Repeat("x", MaxDescriptionBytes+1),
	} {
		if _, found, err := ReadLaunchMarker(bad); err == nil || found {
			t.Fatalf("malformed marker accepted: %q: %v", bad, err)
		}
		if _, err := WithLaunchMarker(bad, m); err == nil {
			t.Fatal("writer overwrote malformed marker")
		}
	}
	for _, change := range []func(*LaunchMarker){
		func(m *LaunchMarker) { m.UUID = "invalid" },
		func(m *LaunchMarker) { m.Account = resource.AccountID{} },
		func(m *LaunchMarker) { m.KeyPair = strings.Repeat("x", 256) },
		func(m *LaunchMarker) { m.Type = "" },
		func(m *LaunchMarker) { m.DOT = make([]string, resource.MaxLaunchVolumes+1) },
	} {
		bad := launchMarker(t)
		change(&bad)
		if _, err := WithLaunchMarker("", bad); err == nil {
			t.Fatalf("invalid marker accepted: %+v", bad)
		}
	}
}

func TestLaunchMarkerRecoversFromPVEConfig(t *testing.T) {
	m := launchMarker(t)
	s := inventoryScenario()
	description, err := WithLaunchMarker("operator note", m)
	if err != nil {
		t.Fatal(err)
	}
	s.VMs[0].Config["description"] = description
	client, _ := serve(t, s)
	for range 2 {
		b, err := New(t.Context(), client, registration(), RegionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := b.client.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
		if err != nil {
			t.Fatal(err)
		}
		got, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil || !found || !reflect.DeepEqual(got, m) {
			t.Fatalf("recreated backend read %+v: %v", got, err)
		}
	}
}

func FuzzLaunchMarkerRoundTrip(f *testing.F) {
	f.Add("team key", "operator note")
	f.Add("key\nfp=other", "vws:v=2")
	f.Fuzz(func(t *testing.T, keyPair, description string) {
		m := launchMarker(t)
		m.KeyPair = keyPair
		encoded, err := WithLaunchMarker(description, m)
		if err != nil {
			return
		}
		got, found, err := ReadLaunchMarker(encoded)
		if err != nil || !found || !reflect.DeepEqual(got, m) || len(encoded) > MaxDescriptionBytes {
			t.Fatalf("round trip %+v: %v", got, err)
		}
	})
}
