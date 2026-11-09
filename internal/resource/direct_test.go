package resource

import (
	"encoding/json"
	"testing"
)

func TestDirectNetworkIDsParse(t *testing.T) {
	for _, s := range []string{
		"subnet-direct-prod", "subnet-direct-a", "subnet-direct-a0-b", "subnet-direct-abcdefghijklmno",
	} {
		id, err := Parse[SubnetID](s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if !IsDirectSubnet(id) {
			t.Fatalf("%s is not direct", s)
		}
	}
	for _, s := range []string{
		"subnet-direct-", "subnet-direct-Prod", "subnet-direct-1prod", "subnet-direct--prod",
		"subnet-direct-abcdefghijklmnop", "subnet-direct-pr_od", "subnet-direct-pröd", "subnet-direct-prod ",
		"subnet-direct", "Subnet-direct-prod",
	} {
		if _, err := Parse[SubnetID](s); CodeOf(err) != CodeInvalidArgument {
			t.Fatalf("%q parsed: %v", s, err)
		}
	}
	vpc, err := Parse[VpcID]("vpc-direct")
	if err != nil || vpc != DirectVpcID() || !IsDirectVpc(vpc) {
		t.Fatalf("vpc-direct: %v %v", vpc, err)
	}
	for _, s := range []string{"vpc-direct2", "vpc-Direct", "vpc-direct-prod", "vpc-dire"} {
		if _, err := Parse[VpcID](s); CodeOf(err) != CodeInvalidArgument {
			t.Fatalf("%q parsed: %v", s, err)
		}
	}
	overlay, err := Parse[SubnetID]("subnet-0123456789abcdef0")
	if err != nil || IsDirectSubnet(overlay) {
		t.Fatalf("minted subnet: %v direct=%v", err, IsDirectSubnet(overlay))
	}
	if IsDirectVpc(VpcID{}) {
		t.Fatal("the zero vpc is direct")
	}
	var req DeleteSubnetRequest
	if err := json.Unmarshal([]byte(`{"subnetId":"subnet-direct-prod"}`), &req); err != nil || !IsDirectSubnet(req.ID) {
		t.Fatalf("json: %v %v", req.ID, err)
	}
}

func TestDirectNetworksAreReadOnly(t *testing.T) {
	direct := mustParseID[SubnetID](t, "subnet-direct-prod")
	overlay := mustParseID[SubnetID](t, "subnet-0123456789abcdef0")
	vpc := mustParseID[VpcID](t, "vpc-0123456789abcdef0")
	tags := map[string]string{"env": "dev"}
	errOf := func(_ any, err error) error { return err }
	cases := []struct {
		name             string
		refused, allowed error
	}{
		{
			"CreateSubnet",
			errOf(CreateSubnetRequest{Cidr: "192.168.200.0/25", VpcID: DirectVpcID()}.Normalize()),
			errOf(CreateSubnetRequest{Cidr: "10.0.0.0/24", VpcID: vpc}.Normalize()),
		},
		{
			"DeleteSubnet",
			errOf(DeleteSubnetRequest{ID: direct}.Normalize()),
			errOf(DeleteSubnetRequest{ID: overlay}.Normalize()),
		},
		{
			"TagSubnets",
			errOf(TagSubnetsRequest{IDs: []SubnetID{overlay, direct}, Tags: tags}.Normalize()),
			errOf(TagSubnetsRequest{IDs: []SubnetID{overlay}, Tags: tags}.Normalize()),
		},
		{
			"TagVpcs",
			errOf(TagVpcsRequest{IDs: []VpcID{vpc, DirectVpcID()}, Tags: tags}.Normalize()),
			errOf(TagVpcsRequest{IDs: []VpcID{vpc}, Tags: tags}.Normalize()),
		},
		{
			"UntagSubnets",
			errOf(UntagSubnetsRequest{IDs: []SubnetID{overlay, direct}}.Normalize()),
			errOf(UntagSubnetsRequest{IDs: []SubnetID{overlay}}.Normalize()),
		},
		{
			"UntagVpcs",
			errOf(UntagVpcsRequest{IDs: []VpcID{vpc, DirectVpcID()}}.Normalize()),
			errOf(UntagVpcsRequest{IDs: []VpcID{vpc}}.Normalize()),
		},
		{
			"DeleteVpc",
			errOf(DeleteVpcRequest{ID: DirectVpcID()}.Normalize()),
			errOf(DeleteVpcRequest{ID: vpc}.Normalize()),
		},
		{
			"CreateSecurityGroup",
			errOf(CreateSecurityGroupRequest{Name: "web", VpcID: DirectVpcID()}.Normalize()),
			errOf(CreateSecurityGroupRequest{Name: "web", VpcID: vpc}.Normalize()),
		},
	}
	for _, c := range cases {
		if CodeOf(c.refused) != CodePermissionDenied {
			t.Errorf("%s on a direct network: %v, want PermissionDenied", c.name, c.refused)
		}
		if c.allowed != nil {
			t.Errorf("%s on an overlay network: %v", c.name, c.allowed)
		}
	}
}

func mustParseID[T any, PT textValue[T]](t *testing.T, s string) T {
	t.Helper()
	v, err := Parse[T, PT](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
