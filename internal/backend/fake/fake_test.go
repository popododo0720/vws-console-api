package fake

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	provider := backend.AllSupported{Kind: resource.RegionKindAWS}
	caps, err := provider.RegionCapabilities(context.Background(), resource.RegionName)
	if err != nil {
		t.Fatal(err)
	}
	backendtest.Run(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	}, caps)
}

// TestDetachReplayContract runs the #213 DetachVolume client-token table on
// the fake.
func TestDetachReplayContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.DetachReplay(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	})
}

// TestBucketCreateContract runs the #315 CreateBucket table on the fake.
func TestBucketCreateContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.BucketCreate(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	})
}

// TestDetachWindowContract runs the #303 DetachVolume record window table on
// the fake.
func TestDetachWindowContract(t *testing.T) {
	backendtest.DetachWindow(t, func() (backend.Set, func(time.Duration)) {
		now := time.Unix(1_700_000_000, 0).UTC()
		var mu sync.Mutex
		clock := func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
		set := New(Options{Now: clock, Entropy: &Sequence{}}).Set()
		return set, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(d)
		}
	})
}

// TestKeyImportContract runs the #279 ImportKeyPair table on the fake.
func TestKeyImportContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.KeyImport(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	})
}

// TestKeyTokenMixContract runs the #281 create and import token table on
// the fake.
func TestKeyTokenMixContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.KeyTokenMix(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	})
}

// TestKeyImportConcurrentContract runs the #287 concurrent import table on
// the fake, which serves each call under one lock.
func TestKeyImportConcurrentContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.KeyImportConcurrent(t, func(int) backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
	})
}

func TestRepeatedEntropyDoesNotOverwrite(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := New(Options{
		Now:     func() time.Time { return now },
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x11}, 1<<12)),
	}).Set()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "sub", Fingerprint: "sub"}, resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	_, err = set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: "run", Fingerprint: "run"}, resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 2,
	})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("collision: %v", err)
	}
	page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("collision published %+v", page.Items)
	}
}

// TestRepeatedEntropyPublishesNoExtraVolume pins #423 AC2 on the fake: an
// extra volume id that repeats one the launch already minted is an internal
// error, and the launch publishes no instance and no volume.
func TestRepeatedEntropyPublishesNoExtraVolume(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	set := New(Options{
		Now:     func() time.Time { return now },
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x22}, 1<<12)),
	}).Set()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "sub", Fingerprint: "sub"},
		resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	_, err = set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: "run", Fingerprint: "run"},
		resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
			ExtraVolumes: []resource.LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8}},
		})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("collision: %v", err)
	}
	insts, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	if len(insts.Items) != 0 || len(vols.Items) != 0 {
		t.Fatalf("collision published %+v and %+v", insts.Items, vols.Items)
	}
}

// TestAttachLifecycleContract runs the #214 attach table on the fake. The
// world settles an operation one second after it is accepted.
func TestAttachLifecycleContract(t *testing.T) {
	backendtest.AttachLifecycle(t, func() (backend.Set, func()) {
		now := time.Unix(1_700_000_000, 0).UTC()
		set := New(Options{Now: func() time.Time { return now }, Latency: time.Second, Entropy: &Sequence{}}).Set()
		return set, func() { now = now.Add(2 * time.Second) }
	})
}

// TestDirectNetworksContract runs the #60 direct network table on the fake.
func TestDirectNetworksContract(t *testing.T) {
	direct, err := resource.Parse[resource.SubnetID](backendtest.DirectSubnet)
	if err != nil {
		t.Fatal(err)
	}
	world := New(Options{Entropy: &Sequence{}, Direct: []DirectNetwork{{ID: direct, Cidr: backendtest.DirectCidr}}})
	backendtest.DirectNetworks(t, world.Set)
}
