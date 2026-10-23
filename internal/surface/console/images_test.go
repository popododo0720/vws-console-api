package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestListImagesReportsOwnerAndPublic(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-00000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	public := resource.Image{ID: id, OwnerID: other, Name: "shared", State: "available", Public: true}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Images: []resource.Image{public}}).Set()})
	h := New(rootConfig(svc, account))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/images", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []struct {
			ImageID string `json:"imageId"`
			OwnerID string `json:"ownerId"`
			Public  bool   `json:"public"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	got := map[string]struct {
		owner  string
		public bool
	}{}
	for _, img := range page.Items {
		got[img.ImageID] = struct {
			owner  string
			public bool
		}{img.OwnerID, img.Public}
	}
	if row := got[id.String()]; row.owner != other.String() || !row.public {
		t.Fatalf("public image %+v", row)
	}
	if row := got["ami-0123456789abcdef0"]; row.owner != account.String() || row.public {
		t.Fatalf("catalog image %+v", row)
	}
	if len(got) != 2 {
		t.Fatalf("images %+v", page.Items)
	}
}
