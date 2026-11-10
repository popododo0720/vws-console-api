package grpcclient

import (
	"context"
	"testing"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// countingVpcWorld is networkStateWorld that counts UpdateVpc calls.
type countingVpcWorld struct {
	*networkStateWorld
	updates int
}

func (w *countingVpcWorld) UpdateVpc(context.Context, *networkv1.UpdateVpcRequest) (*longrunningpb.Operation, error) {
	w.updates++
	return &longrunningpb.Operation{Name: "operations/op-1"}, nil
}

// TestUntagVpcsWritesNothingWhenALaterVpcDoesNotDecode checks that a
// DeleteTags over two VPCs, the second with tag chunks that do not decode,
// is refused before the first VPC is written.
func TestUntagVpcsWritesNothingWhenALaterVpcDoesNotDecode(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodID, badID = "vpc-01234567", "vpc-89abcdef"
	good := observedVpc(projectID, goodID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY)
	good.Labels = map[string]string{"env": "dev"}
	bad := observedVpc(projectID, badID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY)
	bad.Labels = map[string]string{tagChunkKey(0): `{"Owner Team":`}
	world := &countingVpcWorld{networkStateWorld: &networkStateWorld{vpcs: []*networkv1.Vpc{good, bad}}}
	client := dialNetworkStateWorld(t, world)
	ids := make([]resource.VpcID, 0, 2)
	for _, raw := range []string{goodID, badID} {
		id, err := resource.Parse[resource.VpcID](raw)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-untag-bad", Fingerprint: "fp-untag-bad"}
	_, err := client.UntagVpcs(context.Background(), mut, resource.UntagVpcsRequest{IDs: ids})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("UntagVpcs over an undecodable VPC: %v, want Internal", err)
	}
	if world.updates != 0 {
		t.Fatalf("UntagVpcs wrote %d VPCs before refusing", world.updates)
	}
}
