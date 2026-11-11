package backend_test

import (
	"encoding/json"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestScopeRegionRoundTrip(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	want := backend.Scope{Account: account, Region: "pve-seoul-1"}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got backend.Scope
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("scope = %+v, want %+v", got, want)
	}
}
