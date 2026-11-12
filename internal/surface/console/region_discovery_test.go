package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type discoveryCapabilities func(context.Context, string) (resource.RegionCapabilities, error)

func (f discoveryCapabilities) RegionCapabilities(
	ctx context.Context, name string,
) (resource.RegionCapabilities, error) {
	return f(ctx, name)
}

func TestRegionDiscoveryHealthAndReadBound(t *testing.T) {
	e := newLoginEnv(t)
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{
		{Name: "pve-healthy-1"},
		{Name: "pve-noquorum-1"},
		{Name: "pve-leaderless-1"},
		{Name: "pve-stalled-1"},
		{Name: "pve-stalled-2"},
	}, []backend.AWSAccount{{AllowedRegions: []string{"us-east-1", "us-east-1", "us-west-2"}}})
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	caps := discoveryCapabilities(func(ctx context.Context, name string) (resource.RegionCapabilities, error) {
		calls.Add(1)
		if strings.HasPrefix(name, "pve-stalled-") {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("region read has no deadline")
			}
			<-release
			return resource.RegionCapabilities{}, errors.New("late response")
		}
		if name == "us-west-2" {
			return resource.RegionCapabilities{}, errors.New("https://internal.example/token-canary")
		}
		doc := resource.RegionCapabilities{Region: name, Kind: resource.RegionKindAWS}
		if strings.HasPrefix(name, "pve-") {
			doc.Kind = resource.RegionKindProxmox
			doc.Cluster = &resource.RegionCluster{Quorate: name != "pve-noquorum-1", Leader: "pve1"}
			if name == "pve-leaderless-1" {
				doc.Cluster.Leader = ""
			}
		}
		return doc, nil
	})
	e.h.(*handler).svc = cloud.New(cloud.Config{Regions: catalog, Capabilities: caps})
	start := time.Now()
	rec := e.do(t, "GET", "/api/v1/regions", "", map[string]string{"Authorization": "Bearer tok"})
	elapsed := time.Since(start)
	want := `{"items":[` +
		`{"name":"pve-healthy-1","kind":"pve","state":"available"},` +
		`{"name":"pve-leaderless-1","kind":"pve","state":"degraded"},` +
		`{"name":"pve-noquorum-1","kind":"pve","state":"degraded"},` +
		`{"name":"pve-stalled-1","kind":"pve","state":"unavailable"},` +
		`{"name":"pve-stalled-2","kind":"pve","state":"unavailable"},` +
		`{"name":"us-east-1","kind":"aws","state":"available"},` +
		`{"name":"us-west-2","kind":"aws","state":"unavailable"}]}`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want || calls.Load() != 7 {
		t.Fatalf("discovery: %d %s; calls=%d", rec.Code, rec.Body, calls.Load())
	}
	if elapsed < 5*time.Second || elapsed >= 8*time.Second {
		t.Fatalf("parallel regional read bound: %s", elapsed)
	}
}

func TestRegionCapabilitiesUnchangedAndRetry(t *testing.T) {
	e := newLoginEnv(t)
	doc, err := (backend.AllSupported{Kind: resource.RegionKindProxmox}).RegionCapabilities(t.Context(), "pve-test-1")
	if err != nil {
		t.Fatal(err)
	}
	doc.Cluster = &resource.RegionCluster{Name: "test", PVERelease: "9.0", Quorate: true, Leader: "pve1"}
	doc.Zones = []resource.RegionZone{{
		ZoneName: "pve-test-1a", ZoneID: "test-a", State: "available", Nodes: []string{"pve1"},
	}}
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{
		{Name: doc.Region, Endpoint: "https://internal.example"},
	}, nil)
	var calls int
	caps := discoveryCapabilities(func(context.Context, string) (resource.RegionCapabilities, error) {
		calls++
		return doc, nil
	})
	for range 2 {
		e.h.(*handler).svc = cloud.New(cloud.Config{Regions: catalog, Capabilities: caps})
		for range 2 {
			rec := e.do(t, "GET", "/api/v1/regions/"+doc.Region+"/capabilities", "",
				map[string]string{"Authorization": "Bearer tok"})
			var got resource.RegionCapabilities
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 || !reflect.DeepEqual(got, doc) {
				t.Fatalf("capabilities changed: %d %s; %v", rec.Code, rec.Body, err)
			}
		}
	}
	if calls != 4 {
		t.Fatalf("document was cached across retry or restart: %d", calls)
	}
}

func TestRegionCapabilitiesInputAndSafeFailures(t *testing.T) {
	e, _, app, audit := accountFixture(t)
	var calls atomic.Int32
	caps := discoveryCapabilities(func(context.Context, string) (resource.RegionCapabilities, error) {
		calls.Add(1)
		return resource.RegionCapabilities{}, errors.New("token-canary secret-canary https://internal.example")
	})
	e.h.(*handler).svc = cloud.New(cloud.Config{
		Capabilities: caps, Regions: backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}}, nil),
	})
	headers := map[string]string{"Authorization": "Bearer tok"}
	for _, name := range []string{"pve-unknown-1", "PVE-test-1", strings.Repeat("a", 64), "bad%20name"} {
		path := "/api/v1/regions/" + name + "/capabilities"
		rec := e.do(t, "GET", path, "", headers)
		headerResponse := e.do(t, "GET", "/api/v1/regions", "",
			map[string]string{"Authorization": "Bearer tok", "X-Vws-Region": strings.ReplaceAll(name, "%20", " ")})
		if rec.Code != 400 || rec.Body.String() != headerResponse.Body.String() || calls.Load() != 0 {
			t.Fatalf("region validation %q: %d %s; header=%s, calls=%d",
				name, rec.Code, rec.Body, headerResponse.Body, calls.Load())
		}
	}
	for _, path := range []string{
		"/api/v1/regions?secret=canary", "/api/v1/regions/pve-test-1/capabilities?secret=canary",
		"/api/v1/regions/all/capabilities",
	} {
		if rec := e.do(t, "GET", path, "", headers); rec.Code != 400 || calls.Load() != 0 {
			t.Fatalf("boundary %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/api/v1/regions", "/api/v1/regions/pve-test-1/capabilities"} {
		rec := e.do(t, "GET", path, "", headers)
		body := rec.Body.String()
		if (path == "/api/v1/regions" && (rec.Code != 200 || !strings.Contains(body, `"state":"unavailable"`))) ||
			(path != "/api/v1/regions" && (rec.Code != 503 || !strings.Contains(rec.Body.String(), `"code":"Unavailable"`))) {
			t.Fatalf("safe failure: %d %s", rec.Code, rec.Body)
		}
		output := rec.Body.String() + app.String() + audit.String()
		for _, canary := range []string{"token-canary", "secret-canary", "https://internal.example"} {
			if strings.Contains(output, canary) {
				t.Fatalf("canary escaped: %s", output)
			}
		}
	}
}

func TestRegionCapabilitiesStalledRead(t *testing.T) {
	e := newLoginEnv(t)
	release := make(chan struct{})
	defer close(release)
	e.h.(*handler).svc = cloud.New(cloud.Config{Capabilities: discoveryCapabilities(func(
		context.Context, string,
	) (resource.RegionCapabilities, error) {
		<-release
		return resource.RegionCapabilities{}, nil
	})})
	start := time.Now()
	rec := e.do(t, "GET", "/api/v1/regions/"+resource.RegionName+"/capabilities", "",
		map[string]string{"Authorization": "Bearer tok"})
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"code":"Unavailable"`) ||
		time.Since(start) >= 8*time.Second {
		t.Fatalf("stalled read: %d %s after %s", rec.Code, rec.Body, time.Since(start))
	}
}

func TestRegionDiscoveryAuthorizationAndFake(t *testing.T) {
	e := newLoginEnv(t)
	for _, path := range []string{"/api/v1/regions", "/api/v1/regions/" + resource.RegionName + "/capabilities"} {
		if rec := e.do(t, "GET", path, "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous discovery: %d %s", rec.Code, rec.Body)
		}
		user, _ := e.login(t)
		rec := e.do(t, "GET", path, "", nil, user)
		if rec.Code != 200 {
			t.Fatalf("DescribeRegions grant: %d %s", rec.Code, rec.Body)
		}
		if path == "/api/v1/regions" {
			if strings.TrimSpace(rec.Body.String()) != `{"items":[{"name":"vws-1","kind":"pve","state":"available"}]}` {
				t.Fatalf("fake discovery: %s", rec.Body)
			}
		} else {
			doc, err := (backend.AllSupported{Kind: resource.RegionKindProxmox}).RegionCapabilities(
				t.Context(), resource.RegionName,
			)
			want, marshalErr := json.Marshal(doc)
			if err != nil || marshalErr != nil || strings.TrimSpace(rec.Body.String()) != string(want) {
				t.Fatalf("fake document: %s; %v %v", rec.Body, err, marshalErr)
			}
		}
		if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "deny-regions",
			`{"Statement":[{"Effect":"Deny","Action":"ec2:DescribeRegions","Resource":"*"}]}`,
			backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob"),
		); err != nil {
			t.Fatal(err)
		}
		if rec := e.do(t, "GET", path, "", nil, user); rec.Code != 403 {
			t.Fatalf("DescribeRegions denial: %d %s", rec.Code, rec.Body)
		}
		e = newLoginEnv(t)
	}
}
