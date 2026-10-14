package cloud

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestDescribeInstancesFillsPublicIPFromAssociation(t *testing.T) {
	ctx := t.Context()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	c := resource.Caller{Account: account, Subject: "t"}
	svc := New(Config{Backends: fake.New(fake.Options{}).Set()})
	sub, err := svc.CreateSubnet(ctx, c, token(t, "pip-1"), resource.CreateSubnetRequest{Cidr: "10.3.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := svc.RunInstances(ctx, c, token(t, "pip-2"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	inst, other := run.Items[0].ID, run.Items[1].ID
	alloc, err := svc.AllocateAddress(ctx, c, token(t, "pip-3"), resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil {
		t.Fatal(err)
	}
	addr := alloc.Items[0]
	if _, err := svc.AssociateAddress(ctx, c, token(t, "pip-4"), resource.AssociateAddressRequest{ID: addr.ID, InstanceID: inst}); err != nil {
		t.Fatal(err)
	}
	page, err := svc.DescribeInstances(ctx, c, resource.InstanceQuery{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[resource.InstanceID]resource.Instance{}
	for _, item := range page.Items {
		got[item.ID] = item
	}
	if got[inst].PublicIP == "" || got[inst].PublicIP != addr.PublicIP || got[inst].PublicIPAllocationID != addr.ID {
		t.Fatalf("associated instance %+v, address %+v", got[inst], addr)
	}
	if got[other].PublicIP != "" {
		t.Fatalf("unassociated instance has %q", got[other].PublicIP)
	}
	if _, err := svc.DisassociateAddress(ctx, c, token(t, "pip-5"), resource.DisassociateAddressRequest{ID: addr.ID}); err != nil {
		t.Fatal(err)
	}
	page, err = svc.DescribeInstances(ctx, c, resource.InstanceQuery{IDs: []resource.InstanceID{inst}})
	if err != nil {
		t.Fatal(err)
	}
	if page.Items[0].PublicIP != "" {
		t.Fatalf("public ip after disassociate %q", page.Items[0].PublicIP)
	}
}
