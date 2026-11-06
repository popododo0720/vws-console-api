package backendtest

import (
	"context"
	"fmt"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TagsReplay is the CreateTags client-token table (#333). A retry with the
// token and parameters of a CreateTags that succeeded returns that
// operation, even after a detach changed the instance and holds label room
// for its records. The same token with other tags, another instance or the
// instances in another order is a mismatch.
//
// Each backend set gets its own account, so it may share a world with Run.
func TagsReplay(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	account, err := resource.Parse[resource.AccountID]("456789012345")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "tr-" + key, Fingerprint: "fp-tr-" + key}
	}
	first, second := detachInstances(ctx, t, set, scope, mut)

	for _, tc := range []struct {
		name    string
		inst    resource.InstanceID
		tags    int
		settled bool
		device  string
	}{
		{name: "one tag, pending detach", inst: first, tags: 1, device: "/dev/sdf"},
		{name: "one tag, completed detach", inst: first, tags: 1, settled: true, device: "/dev/sdg"},
		{name: "49 tags, pending detach", inst: second, tags: 49, device: "/dev/sdh"},
		{name: "49 tags, completed detach", inst: second, tags: 49, settled: true, device: "/dev/sdi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := fmt.Sprintf("%s-%d-%t", tc.inst, tc.tags, tc.settled)
			tags := make(map[string]string, tc.tags)
			for i := range tc.tags {
				tags[fmt.Sprintf("k%02d", i)] = key
			}
			m := mut("tags-" + key)
			req := resource.CreateTagsRequest{IDs: []resource.InstanceID{tc.inst}, Tags: tags}
			orig, err := set.Compute.CreateTags(ctx, m, req)
			if err != nil {
				t.Fatalf("CreateTags: %v", err)
			}
			vol, err := set.Compute.CreateVolume(ctx, mut("vol-"+key), resource.CreateVolumeRequest{
				SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
				t.Fatal(err)
			}
			volID := vol.Items[0].ID
			if _, err := set.Compute.AttachVolume(ctx, mut("att-"+key), resource.AttachVolumeRequest{
				VolumeID: volID, InstanceID: tc.inst, Device: tc.device,
			}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			det, err := set.Compute.DetachVolume(ctx, mut("det-"+key), resource.DetachVolumeRequest{
				VolumeID: volID, InstanceID: tc.inst,
			})
			if err != nil {
				t.Fatalf("detach: %v", err)
			}
			if tc.settled {
				if _, err := set.Compute.GetOperation(ctx, scope, det.Operation.ID); err != nil {
					t.Fatal(err)
				}
			}

			again, err := set.Compute.CreateTags(ctx, m, req)
			if err != nil {
				t.Fatalf("same-token retry after a detach: %v", err)
			}
			if again.Operation.ID != orig.Operation.ID || again.Operation.Action != resource.ActionCreateTags {
				t.Fatalf("retry gave op %s %s, want the first %s", again.Operation.ID, again.Operation.Action, orig.Operation.ID)
			}
			if len(again.Items) != 1 || again.Items[0].ID != tc.inst {
				t.Fatalf("retry items %+v, want %s", again.Items, tc.inst)
			}
			for k, v := range tags {
				if again.Items[0].Tags[k] != v {
					t.Fatalf("retry item tag %s=%q, want %q", k, again.Items[0].Tags[k], v)
				}
			}

			other := m
			other.Fingerprint += "-other"
			otherReq := resource.CreateTagsRequest{
				IDs: []resource.InstanceID{tc.inst}, Tags: map[string]string{"other": key},
			}
			if _, err := set.Compute.CreateTags(ctx, other, otherReq); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
				t.Fatalf("same token, other tags: %v, want IdempotencyMismatch", err)
			}
		})
	}

	t.Run("another instance or order is a mismatch", func(t *testing.T) {
		tags := map[string]string{"env": "prod"}
		if _, err := set.Compute.CreateTags(ctx, mut("both"), resource.CreateTagsRequest{
			IDs: []resource.InstanceID{first, second}, Tags: tags,
		}); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name      string
			key       string
			first, re []resource.InstanceID
		}{
			{name: "another instance", key: "one", first: []resource.InstanceID{first}, re: []resource.InstanceID{second}},
			{
				name: "another order", key: "pair",
				first: []resource.InstanceID{first, second}, re: []resource.InstanceID{second, first},
			},
		} {
			m := mut(tc.key)
			if _, err := set.Compute.CreateTags(ctx, m, resource.CreateTagsRequest{IDs: tc.first, Tags: tags}); err != nil {
				t.Fatalf("%s: first CreateTags: %v", tc.name, err)
			}
			again := m
			again.Fingerprint += "-" + tc.name
			_, err := set.Compute.CreateTags(ctx, again, resource.CreateTagsRequest{IDs: tc.re, Tags: tags})
			if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
				t.Fatalf("%s, same token: %v, want IdempotencyMismatch", tc.name, err)
			}
		}
	})
}
