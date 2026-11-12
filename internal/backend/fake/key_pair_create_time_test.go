package fake

import (
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func TestKeyPairCreateTime(t *testing.T) {
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range []string{"", pair.Public} {
		t.Run(public, func(t *testing.T) {
			now := time.Date(2026, 11, 10, 6, 30, 0, 0, time.FixedZone("offset", 3600))
			set := New(Options{Now: func() time.Time { return now }, Entropy: &Sequence{}}).Set()
			account, err := resource.Parse[resource.AccountID]("123456789012")
			if err != nil {
				t.Fatal(err)
			}
			m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "key", Fingerprint: "fp"}
			req := resource.CreateKeyPairRequest{Name: "login", Type: resource.KeyTypeEd25519, PublicKey: public}
			created, err := set.Compute.CreateKeyPair(t.Context(), m, req)
			if err != nil {
				t.Fatal(err)
			}
			want := now.UTC()
			if got := created.Items[0].CreateTime; got != want {
				t.Fatalf("created time = %v, want %v", got, want)
			}
			now = now.Add(time.Hour)
			page, err := set.Compute.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{
				Page: resource.PageRequest{Size: 100},
			})
			if err != nil || len(page.Items) != 1 || page.Items[0].CreateTime != want {
				t.Fatalf("describe = %+v %v", page, err)
			}
			if public != "" {
				replayed, err := set.Compute.CreateKeyPair(t.Context(), m, req)
				if err != nil || replayed.Items[0].CreateTime != want {
					t.Fatalf("replayed import = %+v %v", replayed, err)
				}
			}
		})
	}
}
