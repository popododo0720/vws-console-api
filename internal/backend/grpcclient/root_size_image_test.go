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
// is InvalidBlockDeviceMapping before any volume or instance. A size at the
// image is sent to vws-storage as asked, and an omitted one is the image's.
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
	for _, size := range []int64{8, 19} {
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
	for _, c := range []struct {
		key        string
		size, want int64
	}{{"fits", 20, 20}, {"larger", 30, 30}, {"omitted", 0, 20}} {
		if err := run(c.key, c.size); err != nil {
			t.Fatalf("a %d GiB root on a 20 GiB image: %v", c.size, err)
		}
		boot.mu.Lock()
		got := boot.size
		boot.mu.Unlock()
		if got != c.want {
			t.Fatalf("a %d GiB root on a 20 GiB image: storage got %d GiB, want %d", c.size, got, c.want)
		}
	}
}

// #429: an omitted size takes the image's, and the io1 Iops-per-GiB ratio
// is checked on it: 1,000 IOPS need 20 GiB, so they boot a 20 GiB image.
func TestRootIopsRatioIsCheckedOnTheImageSize(t *testing.T) {
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	boot, client := startRegional(t)
	boot.mu.Lock()
	boot.images[registeredAMI] = imageRecord{project: project(mustAccount(t)), region: resource.RegionName, sizeGiB: 20}
	boot.mu.Unlock()
	req, err := resource.RunInstancesRequest{
		ImageID: mustImage(t, registeredAMI), InstanceType: "vws.small", SubnetID: sub, Count: 1,
		RootVolumeType: resource.VolumeIO1, RootIops: 1000,
	}.Normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if _, err := client.RunInstances(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: mustAccount(t)}, Key: "io1-ratio", Fingerprint: "fp-io1-ratio",
	}, req); err != nil {
		t.Fatalf("1,000 io1 IOPS on a 20 GiB image: %v", err)
	}
	boot.mu.Lock()
	got := boot.size
	boot.mu.Unlock()
	if got != 20 {
		t.Fatalf("storage got %d GiB, want 20", got)
	}
}
