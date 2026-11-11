package regionapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestMaximumTaggedInstancePage(t *testing.T) {
	ctx := t.Context()
	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	seedReads(t, set, scope)
	subs, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{Page: resource.PageRequest{Size: 100}})
	if err != nil {
		t.Fatal(err)
	}
	image, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{}
	for i := range resource.MaxTags {
		tags[fmt.Sprintf("%03d%s", i, strings.Repeat("<", 125))] = strings.Repeat("&", 256)
	}
	req, err := (resource.RunInstancesRequest{
		ImageID: image, InstanceType: "vws.small",
		SubnetID: subs.Items[0].ID, Count: 10, Tags: tags,
	}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		key := fmt.Sprintf("page-%d", i)
		m := backend.Mutation{Scope: scope, Key: key, Fingerprint: key}
		if _, err := set.Compute.RunInstances(ctx, m, req); err != nil {
			t.Fatal(err)
		}
	}
	q, err := (resource.InstanceQuery{Page: resource.PageRequest{Size: 100}}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want, err := set.Compute.DescribeInstances(ctx, scope, q)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Items) != 100 || len(encoded) <= 8<<20 {
		t.Fatalf("weak fixture: %d bytes", len(encoded))
	}
	c, _ := loopback(t, config(set))
	var got resource.Page[resource.Instance]
	if err := c.Call(ctx, "Compute", "DescribeInstances", scope, q, &got); err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(encoded) {
		t.Fatal("legal page changed")
	}
}
