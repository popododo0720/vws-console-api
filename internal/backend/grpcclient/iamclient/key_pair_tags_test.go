package iamclient

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func TestKeyPairTagsOnFakeAndRegions(t *testing.T) {
	for _, mode := range []string{"fake", "regions"} {
		for _, imported := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/import=%t", mode, imported), func(t *testing.T) {
				cryptotest.SetGlobalRandom(t, 604)
				server := &keyPairServer{lost: true}
				m := keyPairMutation(t)
				set := fake.New(fake.Options{}).Set()
				if mode == "regions" {
					client := New(keyPairConnection(t, server), Options{Backoff: time.Millisecond})
					var err error
					set, err = regionset.New(backend.NewStaticRegions([]backend.ProxmoxRegion{
						{Name: m.Region},
					}, nil), func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
						t.Fatal("key pairs reached a region transport")
						return nil, resource.Invalid("region", "unexpected key pair transport")
					}, client)
					if err != nil {
						t.Fatal(err)
					}
				}
				svc := cloud.New(cloud.Config{Backends: set})
				call := resource.Caller{Account: m.Account, Region: m.Region}
				want := map[string]string{
					"team": "a", "Name": "login", "vws-key-sha1": "user value",
					"vws-tags-00": "user chunk", "long": strings.Repeat("x", 128),
				}
				req := resource.CreateKeyPairRequest{Name: "login", Tags: maps.Clone(want)}
				if imported {
					pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
					if err != nil {
						t.Fatal(err)
					}
					req.PublicKey = pair.Public
				}
				got, err := svc.CreateKeyPair(t.Context(), call, resource.ClientToken{}, req)
				if err != nil || len(got.Items) != 1 || !maps.Equal(got.Items[0].Tags, want) {
					t.Fatalf("create/import tags = %+v %v", got, err)
				}
				if mode == "regions" {
					server.mu.Lock()
					labels := maps.Clone(server.key.GetLabels())
					server.mu.Unlock()
					if labels["team"] != "a" || labels["vws-tags-00"] == want["vws-tags-00"] {
						t.Fatalf("tags were not encoded on the IAM record: %v", labels)
					}
					if !imported && (labels["vws-key-sha1"] == "" || labels["vws-key-sha1"] == want["vws-key-sha1"]) {
						t.Fatal("user tag overwrote the RSA fingerprint label")
					}
				}
				req.Tags["team"] = "changed request"
				got.Items[0].Tags["team"] = "changed response"
				for range 2 {
					page, err := svc.DescribeKeyPairs(t.Context(), call, resource.KeyPairQuery{})
					if err != nil || len(page.Items) != 1 || !maps.Equal(page.Items[0].Tags, want) {
						t.Fatalf("describe tags = %+v %v", page, err)
					}
					page.Items[0].Tags["team"] = "changed listing"
				}
				many := map[string]string{}
				for i := range resource.MaxTags + 1 {
					many[fmt.Sprintf("k%d", i)] = "v"
				}
				for _, tags := range []map[string]string{{"": "v"}, {"aws:key": "v"}, many} {
					req.Name, req.Tags = "invalid", tags
					_, err := svc.CreateKeyPair(t.Context(), call, resource.ClientToken{}, req)
					if resource.CodeOf(err) != resource.CodeInvalidArgument {
						t.Errorf("invalid tags %v: %v", tags, err)
					}
				}
				req.Name, req.Tags = "fifty", maps.Clone(many)
				delete(req.Tags, "k50")
				if mode == "regions" {
					server.mu.Lock()
					server.key = nil
					server.imports = nil
					server.mu.Unlock()
				}
				got, err = svc.CreateKeyPair(t.Context(), call, resource.ClientToken{}, req)
				if err != nil || len(got.Items) != 1 || len(got.Items[0].Tags) != resource.MaxTags {
					t.Fatalf("50 tags = %+v %v", got, err)
				}
			})
		}
	}
}
