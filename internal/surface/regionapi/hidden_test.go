package regionapi

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type hiddenCompute struct{ backend.Compute }

func (c hiddenCompute) DescribeInstances(ctx context.Context, s backend.Scope, q resource.InstanceQuery) (
	resource.Page[resource.Instance], error,
) {
	page, err := c.Compute.DescribeInstances(ctx, s, q)
	for i := range page.Items {
		id, parseErr := resource.Parse[resource.KeyPairID]("key-0123456789abcdef0")
		if parseErr != nil {
			return page, parseErr
		}
		page.Items[i].KeyPairID = id
		page.Items[i].UserData = "private user data"
		vol, parseErr := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
		if parseErr != nil {
			return page, parseErr
		}
		page.Items[i].DetachingDevices = []resource.BlockDevice{{VolumeID: vol, Device: "/dev/xvdb"}}
	}
	return page, err
}

func TestWireCarriesEveryHiddenModelField(t *testing.T) {
	for _, pair := range []struct{ model, wire reflect.Type }{
		{reflect.TypeFor[resource.Instance](), reflect.TypeFor[wireInstance]()},
		{reflect.TypeFor[resource.SecurityGroup](), reflect.TypeFor[wireSecurityGroup]()},
	} {
		for i := 0; i < pair.model.NumField(); i++ {
			field := pair.model.Field(i)
			if field.Tag.Get("json") != "-" && field.IsExported() {
				continue
			}
			wire, ok := pair.wire.FieldByName(field.Name)
			if !ok || len(wire.Index) != 1 || !wire.IsExported() || wire.Type != field.Type ||
				strings.Split(wire.Tag.Get("json"), ",")[0] == "-" {
				t.Errorf("%s.%s has no explicit transport field", pair.model, field.Name)
			}
		}
	}
}

func TestPublicJSONStillHidesTransportFields(t *testing.T) {
	for _, value := range []any{
		resource.Instance{
			UserData: "private user data", State: resource.InstanceRunning,
			DetachingDevices: []resource.BlockDevice{{Device: "private-device"}},
		},
		resource.SecurityGroup{
			Etag: "private-etag", Labels: map[string]string{"private-label": "value"},
			RuleIDs: []string{"private-rule"},
		},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private") {
			t.Fatalf("public wire leaked transport fields: %s", data)
		}
	}
}

type hiddenNetwork struct{ backend.Network }

func (n hiddenNetwork) DescribeSecurityGroups(ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery) (
	resource.Page[resource.SecurityGroup], error,
) {
	page, err := n.Network.DescribeSecurityGroups(ctx, s, q)
	for i := range page.Items {
		page.Items[i].Etag = "version-1"
		page.Items[i].Labels = map[string]string{"action": "authorize"}
		page.Items[i].RuleIDs = []string{"sgr-0123456789abcdef0"}
	}
	return page, err
}

func TestHiddenReadFieldsRoundTrip(t *testing.T) {
	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	seedReads(t, set, scope)
	set.Compute, set.Network = hiddenCompute{set.Compute}, hiddenNetwork{set.Network}
	c, _ := loopback(t, config(set))
	q := resource.InstanceQuery{Page: resource.PageRequest{Size: 100}}
	want, err := set.Compute.DescribeInstances(t.Context(), scope, q)
	if err != nil {
		t.Fatal(err)
	}
	var got resource.Page[resource.Instance]
	if err := c.Call(t.Context(), "Compute", "DescribeInstances", scope, q, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("instance fields lost: got %#v, want %#v", got, want)
	}
	sq := resource.SecurityGroupQuery{Page: resource.PageRequest{Size: 100}}
	wantGroups, err := set.Network.DescribeSecurityGroups(t.Context(), scope, sq)
	if err != nil {
		t.Fatal(err)
	}
	var gotGroups resource.Page[resource.SecurityGroup]
	if err := c.Call(t.Context(), "Network", "DescribeSecurityGroups", scope, sq, &gotGroups); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotGroups, wantGroups) {
		t.Errorf("security group fields lost: got %#v, want %#v", gotGroups, wantGroups)
	}
}
