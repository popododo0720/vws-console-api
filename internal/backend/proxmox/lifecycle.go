package proxmox

import "github.com/popododo0720/vws-console-api/internal/resource"

// InstanceTransitions returns the EC2 lifecycle edges checked by instance.tla.
// Each call returns its own table so callers cannot change another's policy.
func InstanceTransitions() [][2]resource.InstanceState {
	return [][2]resource.InstanceState{
		{resource.InstancePending, resource.InstanceRunning},
		{resource.InstancePending, resource.InstanceShuttingDown},
		{resource.InstanceRunning, resource.InstanceRunning},
		{resource.InstanceRunning, resource.InstanceStopping},
		{resource.InstanceRunning, resource.InstanceShuttingDown},
		{resource.InstanceStopping, resource.InstanceStopped},
		{resource.InstanceStopping, resource.InstanceShuttingDown},
		{resource.InstanceStopped, resource.InstancePending},
		{resource.InstanceStopped, resource.InstanceShuttingDown},
		{resource.InstanceShuttingDown, resource.InstanceTerminated},
	}
}
