package fake

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.Run(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
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
