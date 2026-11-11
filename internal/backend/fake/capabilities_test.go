package fake

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type brokenStart struct{ backend.Compute }

func (brokenStart) StartInstances(context.Context, backend.Mutation,
	resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, resource.Invalid(
		"StartInstances",
		"broken supported start",
	)
}

type noAddresses struct{ backend.Network }

func (noAddresses) AllocateAddress(context.Context, backend.Mutation,
	resource.AllocateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{}, resource.Unsupported("AllocateAddress", "no elastic IP")
}

func TestRegionWithoutAddresses(t *testing.T) {
	if mode := os.Getenv("VWS_NO_ADDRESS_CHILD"); mode != "" {
		caps, err := (backend.AllSupported{Kind: resource.RegionKindAWS}).RegionCapabilities(
			t.Context(),
			resource.RegionName,
		)
		if err != nil {
			t.Fatal(err)
		}
		caps.Actions[resource.ActionAllocateAddress.CapabilityKey()] = resource.ActionCapability{
			State: resource.ActionUnsupported, Reason: "no elastic IP", ReasonCode: "NoElasticIP",
		}
		backendtest.Run(t, func() backend.Set {
			set := New(Options{Entropy: &Sequence{}}).Set()
			set.Network = noAddresses{set.Network}
			if mode == "broken" {
				set.Compute = brokenStart{set.Compute}
			}
			return set
		}, caps)
		return
	}
	for _, mode := range []string{"good", "broken"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRegionWithoutAddresses$", "-test.v")
		cmd.Env = append(os.Environ(), "VWS_NO_ADDRESS_CHILD="+mode)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (mode == "good") ||
			(mode == "broken" && !strings.Contains(string(out), "partial start: InvalidArgument: broken supported start")) {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		if mode == "good" {
			if strings.Count(string(out), "--- SKIP:") != 3 {
				t.Fatalf("unexpected skipped scenarios:\n%s", out)
			}
			for _, want := range []string{
				"--- PASS: TestRegionWithoutAddresses/EC2",
				"--- SKIP: TestRegionWithoutAddresses/EC2/AddressAssociation",
				"--- SKIP: TestRegionWithoutAddresses/EC2/AddressRelease", "--- SKIP: TestRegionWithoutAddresses/TerminateRelease",
			} {
				if !strings.Contains(string(out), want) {
					t.Fatalf("missing %q:\n%s", want, out)
				}
			}
		}
	}
}
