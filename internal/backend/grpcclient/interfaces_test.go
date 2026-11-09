package grpcclient

import (
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestInterfaceAddressesFollowTheDeviceName pins that each interface's
// address is the status entry of its own device name. Compute need not list
// the spec or the status in device order.
func TestInterfaceAddressesFollowTheDeviceName(t *testing.T) {
	overlay := parsed[resource.SubnetID](t, "subnet-0123456789abcdef0")
	direct := parsed[resource.SubnetID](t, "subnet-direct-prod")
	vpc := parsed[resource.VpcID](t, "vpc-0123456789abcdef0")
	inst := resource.Instance{
		ID:            parsed[resource.InstanceID](t, "i-0123456789abcdef0"),
		ReservationID: parsed[resource.ReservationID](t, "r-0123456789abcdef0"),
		ImageID:       parsed[resource.ImageID](t, "ami-0123456789abcdef0"),
		InstanceType:  "vws.small", State: resource.InstanceRunning,
	}
	inst.SetInterfaces([]resource.NetworkInterface{
		{DeviceIndex: 0, SubnetID: direct, VpcID: resource.DirectVpcID(), PrivateIP: "192.168.200.7"},
		{DeviceIndex: 1, SubnetID: overlay, VpcID: vpc, PrivateIP: "10.0.0.5"},
	})
	vpcOf := func(id resource.SubnetID) string {
		if resource.IsDirectSubnet(id) {
			return "vpc-direct"
		}
		return vpc.String()
	}
	msg := instanceProto(inst, project(parsed[resource.AccountID](t, "123456789012")), vpcOf)
	slices.Reverse(msg.Spec.NetworkInterfaces)
	slices.Reverse(msg.Status.NetworkInterfaces)
	got, err := instanceModel(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.NetworkInterfaces, inst.NetworkInterfaces) {
		t.Fatalf("interfaces %+v, want %+v", got.NetworkInterfaces, inst.NetworkInterfaces)
	}
	if got.SubnetID != direct || got.VpcID != resource.DirectVpcID() || got.PrivateIP != "192.168.200.7" {
		t.Fatalf("instance on %s %s %s, want the device 0 interface", got.SubnetID, got.VpcID, got.PrivateIP)
	}
	msg.Spec.NetworkInterfaces[0].DeviceName = "nic0"
	if _, err := instanceModel(msg); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("two interfaces on device 0: %v, want a bad record", err)
	}
}

func parsed[T any, PT interface {
	*T
	UnmarshalText([]byte) error
}](t *testing.T, s string) T {
	t.Helper()
	v, err := resource.Parse[T, PT](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
