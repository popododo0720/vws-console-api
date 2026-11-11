package backend_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestConsoleCapabilityFollowsBackendSet(t *testing.T) {
	provider := backend.AllSupported{Kind: resource.RegionKindProxmox}
	for _, enabled := range []bool{false, true} {
		set := fake.New(fake.Options{}).Set()
		want := resource.ActionSupported
		if !enabled {
			set.Console = nil
			want = resource.ActionUnsupported
		}
		doc, err := set.Capabilities(provider).RegionCapabilities(t.Context(), resource.RegionName)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.Validate(); err != nil {
			t.Fatal(err)
		}
		if got := doc.Actions["vws:OpenConsole"]; got.State != want {
			t.Errorf("console enabled=%v: got %v, want %v", enabled, got, want)
		}
	}
}
