package grpcclient

import (
	"context"
	"strings"
	"testing"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCreateSnapshotRefusesPackedTagOverflow(t *testing.T) {
	tags := map[string]string{}
	for i := range 20 {
		tags[strings.Repeat("K", 127)+string(rune('a'+i))] = strings.Repeat("v", 256)
	}
	client := computeClient{&api{}}
	_, err := client.CreateSnapshot(context.Background(),
		backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}},
		resource.CreateSnapshotRequest{Tags: tags})
	if !resource.IsTagLimitExceeded(resource.AsError(err)) {
		t.Fatalf("packed tags must be refused before any RPC: %v", err)
	}
}

func TestUndecodableSnapshotTagsAreSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodID, badID = "snap-0123456789abcdef0", "snap-0fedcba9876543210"
	volume := volumeName(projectID, "vol-0123456789abcdef0")
	client, _, logs := dialInvalidCatalogWorld(t, &invalidCatalogWorld{
		snaps: []*storagev1.Snapshot{
			{
				Name: snapshotName(projectID, goodID), Spec: &storagev1.SnapshotSpec{Volume: volume},
				Labels: map[string]string{"env": "dev"},
			},
			{
				Name: snapshotName(projectID, badID), Spec: &storagev1.SnapshotSpec{Volume: volume},
				Labels: map[string]string{tagChunkKey(0): `{"Name":`},
			},
		},
	})
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	page, err := client.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID.String() != goodID || page.Items[0].Tags["env"] != "dev" {
		t.Fatalf("listing: %+v %v", page.Items, err)
	}
	if !strings.Contains(logs.String(), "id="+badID) || strings.Contains(logs.String(), account.String()) {
		t.Fatalf("bad record log: %s", logs.String())
	}
	id, err := resource.Parse[resource.SnapshotID](badID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{IDs: []resource.SnapshotID{id}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("explicit read must refuse undecodable tags: %v", err)
	}
}
