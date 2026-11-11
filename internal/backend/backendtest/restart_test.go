package backendtest_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type emptyRestartSubnet struct{ backend.Network }

func (n emptyRestartSubnet) CreateSubnet(
	ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	got, err := n.Network.CreateSubnet(ctx, m, req)
	got.Items = nil
	return got, err
}

type emptyRestartInstance struct{ backend.Compute }

func (c emptyRestartInstance) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	got, err := c.Compute.RunInstances(ctx, m, req)
	got.Items = nil
	return got, err
}

func TestRestartRejectsEmptyBackendResults(t *testing.T) {
	if mode := os.Getenv("VWS_RESTART_EMPTY_CHILD"); mode != "" {
		backendtest.RebootAndConsoleAcrossRestart(t, func() func() backend.Set {
			world := fake.New(fake.Options{Entropy: &fake.Sequence{}})
			return func() backend.Set {
				set := world.Set()
				if mode == "subnet" {
					set.Network = emptyRestartSubnet{set.Network}
				} else {
					set.Compute = emptyRestartInstance{set.Compute}
				}
				return set
			}
		})
		return
	}
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"subnet", "CreateSubnet returned 0 items, want 1"},
		{"instance", "RunInstances returned 0 items, want 1"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRestartRejectsEmptyBackendResults$", "-test.v")
			cmd.Env = append(os.Environ(), "VWS_RESTART_EMPTY_CHILD="+tc.mode)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) || strings.Contains(string(out), "panic:") {
				t.Fatalf("empty %s result: %v\n%s", tc.mode, err, out)
			}
		})
	}
}
