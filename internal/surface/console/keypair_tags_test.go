package console

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestKeyPairTags(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(rootConfig(svc, account))
	do := func(method, path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1 me@laptop"
	for i, body := range []string{
		`{"keyName":"made","tags":{"Name":"made","team":"a"}}`,
		`{"keyName":"imported","publicKeyMaterial":"` + pub + `","tags":{"Name":"imported","team":"a"}}`,
	} {
		if rec := do(http.MethodPost, "/api/v1/key-pairs", body, fmt.Sprintf("kp-%d", i)); rec.Code != http.StatusAccepted {
			t.Fatalf("create %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	rec := do(http.MethodGet, "/api/v1/key-pairs", "", "")
	var list struct {
		Items []struct {
			Name string            `json:"keyName"`
			Tags map[string]string `json:"tags"`
		} `json:"items"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 2 {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	for _, k := range list.Items {
		if want := map[string]string{"Name": k.Name, "team": "a"}; !maps.Equal(k.Tags, want) {
			t.Errorf("%s: tags %v, want %v", k.Name, k.Tags, want)
		}
	}
	many := map[string]string{}
	for i := range resource.MaxTags + 1 {
		many[fmt.Sprint("k", i)] = "v"
	}
	raw, err := json.Marshal(many)
	if err != nil {
		t.Fatal(err)
	}
	for name, tags := range map[string]string{
		"reserved key": `{"aws:x":"v"}`, "empty key": `{"":"v"}`, "51 tags": string(raw),
	} {
		for _, public := range []string{"", pub} {
			body := `{"keyName":"bad","publicKeyMaterial":"` + public + `","tags":` + tags + `}`
			rec := do(http.MethodPost, "/api/v1/key-pairs", body, "kp-bad-"+name)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: %d %s, want 400", name, rec.Code, rec.Body)
			}
		}
	}
}
