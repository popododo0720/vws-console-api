package regionapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/proxmoxtest"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestProxmoxInstanceRoundTrip(t *testing.T) {
	scope := testScope(t)
	scope.Region = "pve-test-1"
	for range 2 {
		b := proxmoxtest.New(t)
		cfg := config(b.Set())
		cfg.Region, cfg.Capabilities = scope.Region, b
		client, _ := loopback(t, cfg)
		remote, err := regionclient.New(client)
		if err != nil {
			t.Fatal(err)
		}
		want, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
		if err != nil || len(want.Items) != 1 {
			t.Fatalf("direct inventory: %+v, %v", want, err)
		}
		for range 2 {
			got, err := remote.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
			if err != nil || len(got.Items) != 1 {
				t.Fatalf("round trip: %+v, %v; want %+v", got, err, want)
			}
			actual, expected := got.Items[0], want.Items[0]
			if actual.ID != expected.ID || actual.State != expected.State ||
				actual.ReservationID.IsZero() || actual.ReservationID != expected.ReservationID {
				t.Fatalf("round trip identity: %+v; want %+v", actual, expected)
			}
		}
	}
}

func TestProxmoxInstanceWithoutSubnet(t *testing.T) {
	b := proxmoxtest.New(t)
	page, err := b.DescribeInstances(t.Context(), testScope(t), resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 || !page.Items[0].SubnetID.IsZero() {
		t.Fatalf("subnetless inventory: %+v, %v", page, err)
	}
	data, err := json.Marshal(encodeResult(page))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"subnetId"`) {
		t.Fatalf("absent subnet serialized: %s", data)
	}
	var decoded resource.Page[resource.Instance]
	if err := decodeResult(data, &decoded); err != nil || len(decoded.Items) != 1 {
		t.Fatalf("subnetless page: %+v, %v", decoded, err)
	}
	if !decoded.Items[0].SubnetID.IsZero() || decoded.Items[0].ID != page.Items[0].ID {
		t.Fatalf("subnetless instance changed: %+v", decoded.Items[0])
	}
}
