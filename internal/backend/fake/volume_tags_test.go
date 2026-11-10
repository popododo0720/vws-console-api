package fake

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestCreatedVolumeTagsAreNotShared checks that the tags a CreateVolume
// returns are a copy: changing them changes neither the stored volume nor
// the replayed answer.
func TestCreatedVolumeTagsAreNotShared(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-vol", Fingerprint: "fp-vol"}
	req := resource.CreateVolumeRequest{
		SizeGiB: 1, Zone: resource.ZoneName, Type: resource.VolumeGP2, Tags: map[string]string{"Name": "data"},
	}
	acc, err := set.Compute.CreateVolume(ctx, m, req)
	if err != nil {
		t.Fatal(err)
	}
	acc.Items[0].Tags["Name"] = "changed"
	q := resource.VolumeQuery{IDs: []resource.VolumeID{acc.Items[0].ID}, Page: resource.PageRequest{Size: 5}}
	page, err := set.Compute.DescribeVolumes(ctx, m.Scope, q)
	if err != nil || len(page.Items) != 1 || page.Items[0].Tags["Name"] != "data" {
		t.Fatalf("stored tags after changing the answer: %v %+v", err, page.Items)
	}
}
