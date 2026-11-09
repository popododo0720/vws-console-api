package cloud

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestInterfaceOrderKeepsTheFingerprint(t *testing.T) {
	c, token, req := fixedRequest(t)
	direct, err := resource.Parse[resource.SubnetID]("subnet-direct-prod")
	if err != nil {
		t.Fatal(err)
	}
	overlay := req.SubnetID
	req.SubnetID = resource.SubnetID{}
	fingerprint := func(nics ...resource.NetworkInterfaceSpec) string {
		t.Helper()
		r := req
		r.NetworkInterfaces = nics
		norm, err := r.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		m, err := mutation(c, token, norm)
		if err != nil {
			t.Fatal(err)
		}
		return m.Fingerprint
	}
	on := func(i int, sub resource.SubnetID) resource.NetworkInterfaceSpec {
		return resource.NetworkInterfaceSpec{DeviceIndex: i, SubnetID: sub}
	}
	a := fingerprint(on(0, overlay), on(1, direct))
	b := fingerprint(on(1, direct), on(0, overlay))
	if a != b {
		t.Fatalf("listing order changed the fingerprint: %s, %s", a, b)
	}
	swapped := fingerprint(on(0, direct), on(1, overlay))
	if swapped == a {
		t.Fatal("moving the primary interface kept the fingerprint")
	}
}
