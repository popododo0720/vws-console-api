package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type datedKeyPairs struct {
	backend.Compute
	created time.Time
}

func (k datedKeyPairs) DescribeKeyPairs(
	_ context.Context, s backend.Scope, _ resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return resource.Page[resource.KeyPair]{
		Items: []resource.KeyPair{{OwnerID: s.Account, Name: "login", CreateTime: k.created}},
	}, nil
}

func TestKeyPairCreateTimeJSON(t *testing.T) {
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-a-1"}}, nil)
	for _, created := range []time.Time{time.Date(2026, 11, 10, 6, 30, 0, 0, time.UTC), {}} {
		t.Run(created.String(), func(t *testing.T) {
			set, err := regionset.New(catalog, func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
				return nil, errors.New("key pair read reached a regional transport")
			}, datedKeyPairs{created: created})
			if err != nil {
				t.Fatal(err)
			}
			rec := inventoryGET(t, inventoryHandler(t, set, catalog), "key-pairs", "pve-a-1")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET key pairs = %d %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			if created.IsZero() {
				if strings.Contains(body, "createTime") {
					t.Fatalf("undated key = %s, want no createTime", body)
				}
			} else if !strings.Contains(body, `"createTime":"2026-11-10T06:30:00Z"`) {
				t.Fatalf("dated key = %s", body)
			}
		})
	}
}
