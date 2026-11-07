package backendtest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRootVolumeSize covers #423 and #429: the root mapping's
// Ebs.VolumeSize is the size of the root volume, and a size below the
// catalog image, or an Iops ratio the image's size does not allow, is
// refused before any volume or instance is created.
func exerciseRootVolumeSize(
	ctx context.Context, t *testing.T, set backend.Set,
	account resource.AccountID, subnet resource.SubnetID, img resource.ImageID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	for _, size := range []int64{resource.RootVolumeSizeGiB, 20} {
		key := fmt.Sprintf("k-root-size-%d", size)
		run, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key},
			resource.RunInstancesRequest{
				ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, RootVolumeSize: size,
			})
		if err != nil {
			t.Fatalf("run with a %d GiB root: %v", size, err)
		}
		got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			IDs: []resource.InstanceID{run.Items[0].ID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(got.Items) != 1 || len(got.Items[0].BlockDevices) != 1 {
			t.Fatalf("describe with a %d GiB root: %v %+v", size, err, got.Items)
		}
		vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{got.Items[0].BlockDevices[0].VolumeID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(vols.Items) != 1 || vols.Items[0].SizeGiB != size {
			t.Fatalf("a %d GiB root reads back as %v %+v", size, err, vols.Items)
		}
	}
	before := countLaunched(ctx, t, set, scope)
	key := "k-root-size-below-image"
	_, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key},
		resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, RootVolumeSize: resource.RootVolumeSizeGiB - 1,
		})
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeInvalidArgument || re.Field != "blockDeviceMapping" {
		t.Fatalf("a root below the image: %v", err)
	}
	// #429: an omitted size is the image's, and the Iops-per-GiB ratio is
	// checked on it: 1,000 io1 IOPS are above 50 per GiB on the 8 GiB image.
	key = "k-root-ratio-on-image"
	_, err = set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key},
		resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1,
			RootVolumeType: resource.VolumeIO1, RootIops: 1000,
		})
	if !errors.As(err, &re) || re.Code != resource.CodeInvalidArgument || re.Field != "iops" {
		t.Fatalf("1,000 io1 IOPS on the 8 GiB image: %v", err)
	}
	if after := countLaunched(ctx, t, set, scope); after != before {
		t.Fatalf("a refused root size created resources: %v, then %v", before, after)
	}
}

// countLaunched is the number of instances and volumes the account holds.
func countLaunched(ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope) [2]int {
	t.Helper()
	var n [2]int
	for token := ""; ; {
		page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			Page: resource.PageRequest{Size: 100, Token: token},
		})
		if err != nil {
			t.Fatalf("describe instances: %v", err)
		}
		n[0] += len(page.Items)
		if token = page.NextToken; token == "" {
			break
		}
	}
	for token := ""; ; {
		page, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			Page: resource.PageRequest{Size: 100, Token: token},
		})
		if err != nil {
			t.Fatalf("describe volumes: %v", err)
		}
		n[1] += len(page.Items)
		if token = page.NextToken; token == "" {
			break
		}
	}
	return n
}
