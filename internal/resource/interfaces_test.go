package resource

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestRunInstancesNetworkInterfaces(t *testing.T) {
	img := mustParseID[ImageID](t, "ami-0123456789abcdef0")
	overlay := mustParseID[SubnetID](t, "subnet-0123456789abcdef0")
	direct := mustParseID[SubnetID](t, "subnet-direct-prod")
	launch := func(sub SubnetID, nics ...NetworkInterfaceSpec) RunInstancesRequest {
		return RunInstancesRequest{ImageID: img, InstanceType: "vws.small", SubnetID: sub, NetworkInterfaces: nics}
	}
	primary := NetworkInterfaceSpec{0, direct}
	norm, err := launch(SubnetID{}, NetworkInterfaceSpec{1, overlay}, NetworkInterfaceSpec{0, direct}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := []NetworkInterfaceSpec{{0, direct}, {1, overlay}}
	if !slices.Equal(norm.NetworkInterfaces, want) || !norm.SubnetID.IsZero() || !slices.Equal(norm.Interfaces(), want) {
		t.Fatalf("normalized %+v subnet %v, want %+v and no subnet", norm.NetworkInterfaces, norm.SubnetID, want)
	}
	single, err := launch(overlay).Normalize()
	if err != nil || len(single.NetworkInterfaces) != 0 {
		t.Fatalf("SubnetID alone: %v %+v", err, single.NetworkInterfaces)
	}
	if got := single.Interfaces(); !slices.Equal(got, []NetworkInterfaceSpec{{0, overlay}}) {
		t.Fatalf("SubnetID alone is %+v, want device 0 on it", got)
	}
	nine := make([]NetworkInterfaceSpec, 0, MaxNetworkInterfaces+1)
	for i := range MaxNetworkInterfaces + 1 {
		nine = append(nine, NetworkInterfaceSpec{i, overlay})
	}
	for name, c := range map[string]struct {
		req         RunInstancesRequest
		combination bool
	}{
		"subnet and interfaces": {launch(overlay, primary), true},
		"no device 0":           {launch(SubnetID{}, NetworkInterfaceSpec{1, direct}), false},
		"duplicate index":       {launch(SubnetID{}, primary, NetworkInterfaceSpec{0, overlay}), false},
		"negative index":        {launch(SubnetID{}, primary, NetworkInterfaceSpec{-1, overlay}), false},
		"index past the cap":    {launch(SubnetID{}, primary, NetworkInterfaceSpec{8, overlay}), false},
		"missing subnet":        {launch(SubnetID{}, primary, NetworkInterfaceSpec{1, SubnetID{}}), false},
		"too many":              {launch(SubnetID{}, nine...), false},
		"neither":               {launch(SubnetID{}), false},
		"two overlay": {
			launch(SubnetID{}, NetworkInterfaceSpec{0, overlay}, NetworkInterfaceSpec{1, overlay}), false,
		},
	} {
		_, err := c.req.Normalize()
		e := AsError(err)
		if CodeOf(err) != CodeInvalidArgument || IsInvalidCombination(e) != c.combination {
			t.Errorf("%s: %v, want invalid (combination %v)", name, err, c.combination)
		}
	}
}

func TestSetInterfacesKeepsThePrimaryOnTheInstance(t *testing.T) {
	overlay := mustParseID[SubnetID](t, "subnet-0123456789abcdef0")
	direct := mustParseID[SubnetID](t, "subnet-direct-prod")
	vpc := mustParseID[VpcID](t, "vpc-0123456789abcdef0")
	var inst Instance
	inst.SetInterfaces([]NetworkInterface{
		{DeviceIndex: 1, SubnetID: overlay, VpcID: vpc, PrivateIP: "10.0.0.5"},
		{DeviceIndex: 0, SubnetID: direct, VpcID: DirectVpcID(), PrivateIP: "192.168.200.7"},
	})
	if inst.SubnetID != direct || inst.VpcID != DirectVpcID() || inst.PrivateIP != "192.168.200.7" {
		t.Fatalf("instance fields %v %v %s, want the device 0 interface", inst.SubnetID, inst.VpcID, inst.PrivateIP)
	}
	if got := inst.Interfaces(); len(got) != 2 || got[0].DeviceIndex != 0 || got[1].DeviceIndex != 1 {
		t.Fatalf("interfaces %+v, want device order", got)
	}
}

func TestNetworkInterfaceSpecRequiresADeviceIndex(t *testing.T) {
	var got NetworkInterfaceSpec
	err := json.Unmarshal([]byte(`{"deviceIndex":0,"subnetId":"subnet-direct-prod"}`), &got)
	if err != nil || got.DeviceIndex != 0 || got.SubnetID.String() != "subnet-direct-prod" {
		t.Fatalf("explicit device 0: %+v %v", got, err)
	}
	for name, body := range map[string]string{
		"missing index": `{"subnetId":"subnet-direct-prod"}`,
		"unknown field": `{"deviceIndex":0,"subnetId":"subnet-direct-prod","privateIpAddress":"192.168.200.9"}`,
		"bad subnet":    `{"deviceIndex":0,"subnetId":"subnet-direct-UPPER"}`,
		"string index":  `{"deviceIndex":"0","subnetId":"subnet-direct-prod"}`,
	} {
		var spec NetworkInterfaceSpec
		err := json.Unmarshal([]byte(body), &spec)
		if CodeOf(err) != CodeInvalidArgument {
			t.Errorf("%s: %v, want invalid", name, err)
		}
		if name == "missing index" && !IsMissingParameter(AsError(err)) {
			t.Errorf("missing index: %v, want MissingParameter", err)
		}
	}
}
