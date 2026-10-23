package cloud

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestPreviousReleaseIdempotencyRecord decodes the mutation the previous
// released build wrote for a DetachVolume client token and rebuilds it with
// the current derivation. A changed key or fingerprint fails here.
func TestPreviousReleaseIdempotencyRecord(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/upgrade/ceaf591/idempotency.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Account     string                       `json:"account"`
		Subject     string                       `json:"subject"`
		Action      string                       `json:"action"`
		ClientToken string                       `json:"clientToken"`
		Request     resource.DetachVolumeRequest `json:"request"`
		Key         string                       `json:"key"`
		Fingerprint string                       `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Action != resource.ActionDetachVolume.String() {
		t.Fatalf("fixture action %q, want %q", f.Action, resource.ActionDetachVolume)
	}
	account, err := resource.Parse[resource.AccountID](f.Account)
	if err != nil {
		t.Fatal(err)
	}
	token, err := resource.Parse[resource.ClientToken](f.ClientToken)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.Request.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	m, err := mutation(resource.Caller{Account: account, Subject: f.Subject}, token, req)
	if err != nil {
		t.Fatal(err)
	}
	if m.Key != f.Key {
		t.Fatalf("key %s, want the previous release's %s", m.Key, f.Key)
	}
	if m.Fingerprint != f.Fingerprint {
		t.Fatalf("fingerprint %s, want the previous release's %s", m.Fingerprint, f.Fingerprint)
	}
}
