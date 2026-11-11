package regionapi

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAdapterRecreationAndRepeatedReads(t *testing.T) {
	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	scope.Region = "pve-test"
	seedReads(t, set, scope)
	c, srv := loopback(t, config(set))
	cfg := c.http.Transport.(*http.Transport).TLSClientConfig
	q := resource.InstanceQuery{Page: resource.PageRequest{Size: 100}}
	want, err := set.Compute.DescribeInstances(t.Context(), scope, q)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		remote, err := regionclient.New(c)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			got, err := remote.Compute.DescribeInstances(t.Context(), scope, q)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("read after recreation = %+v, %v; want %+v", got, err, want)
			}
		}
		_, err = remote.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{
			Page: resource.PageRequest{Size: 100, Token: "forged:foreign-region-token"},
		})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("forged page token error = %v", err)
		}
		c.Close()
		c, err = NewClient(srv.URL, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
	}
}
