package fake

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCreatedSnapshotTagsAreNotShared(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	set := New(Options{Entropy: &Sequence{}}).Set()
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	vol, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "vol"},
		resource.CreateVolumeRequest{SizeGiB: 8, Type: resource.VolumeGP2, Zone: resource.ZoneName})
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{"Name": "backup"}
	acc, err := set.Compute.CreateSnapshot(ctx, backend.Mutation{Scope: scope, Key: "snap"},
		resource.CreateSnapshotRequest{VolumeID: vol.Items[0].ID, Tags: tags})
	if err != nil {
		t.Fatal(err)
	}
	tags["Name"] = "request changed"
	acc.Items[0].Tags["Name"] = "answer changed"
	q := resource.SnapshotQuery{IDs: []resource.SnapshotID{acc.Items[0].ID}, Page: resource.PageRequest{Size: 5}}
	page, err := set.Compute.DescribeSnapshots(ctx, scope, q)
	if err != nil || len(page.Items) != 1 || page.Items[0].Tags["Name"] != "backup" {
		t.Fatalf("stored snapshot: %+v %v", page.Items, err)
	}
	page.Items[0].Tags["Name"] = "describe changed"
	page, err = set.Compute.DescribeSnapshots(ctx, scope, q)
	if err != nil || len(page.Items) != 1 || page.Items[0].Tags["Name"] != "backup" {
		t.Fatalf("stored snapshot after describe: %+v %v", page.Items, err)
	}
}
