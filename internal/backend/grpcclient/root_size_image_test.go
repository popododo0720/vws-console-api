package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #423: a root volume below the size compute reports for a registered image
// is InvalidBlockDeviceMapping before any volume or instance, and one at the
// image size is sent to vws-storage as asked.
func TestRootVolumeBelowARegisteredImageIsRefused(t *testing.T) {
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	boot, client := startRegional(t)
	boot.mu.Lock()
	boot.images[registeredAMI] = imageRecord{project: project(mustAccount(t)), region: resource.RegionName, sizeGiB: 20}
	boot.mu.Unlock()
	run := func(key string, size int64) error {
		_, err := client.RunInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: key, Fingerprint: "fp-" + key,
		}, resource.RunInstancesRequest{
			ImageID: mustImage(t, registeredAMI), InstanceType: "vws.small", SubnetID: sub, Count: 1, RootVolumeSize: size,
		})
		return err
	}
	for _, size := range []int64{0, 19} {
		err := run(fmt.Sprintf("below-%d", size), size)
		var re *resource.Error
		if !errors.As(err, &re) || re.Code != resource.CodeInvalidArgument || re.Field != "blockDeviceMapping" {
			t.Fatalf("a %d GiB root on a 20 GiB image: %v", size, err)
		}
	}
	boot.mu.Lock()
	volumes, instances := boot.volumes, boot.instances
	boot.mu.Unlock()
	if volumes != 0 || instances != 0 {
		t.Fatalf("a refused root created %d volumes and %d instances", volumes, instances)
	}
	if err := run("fits", 20); err != nil {
		t.Fatalf("a 20 GiB root on a 20 GiB image: %v", err)
	}
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.size != 20 {
		t.Fatalf("storage got a %d GiB boot volume, want 20", boot.size)
	}
}
