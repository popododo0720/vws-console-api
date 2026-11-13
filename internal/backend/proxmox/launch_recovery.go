package proxmox

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// LaunchFailureTag is persisted by finalize before cleanup. A failed VM and its
// marker must survive while its operation is readable; deleting all carriers
// ends replay, just as terminating a successful launch does.
const LaunchFailureTag = "vws.launch.failed"

// LaunchRecovery describes allocated indexes, including unfinished clones.
// Missing indexes in [0, Count) have not been allocated.
type LaunchRecovery struct {
	Instances   map[int]resource.InstanceID
	Count       int
	Reservation resource.ReservationID
	Operation   resource.Operation
}

// RecoverLaunch reads only the bound pool. Finalize retains the full marker:
// tag prefixes cannot prove full-key equality or recover the expected count.
func (b *Backend) RecoverLaunch(ctx context.Context, s backend.Scope, key, fingerprint string) (LaunchRecovery, error) {
	op, err := newLaunchOperation(b.cluster, key)
	if err != nil || !launchHex(fingerprint, 64) {
		return LaunchRecovery{}, fmt.Errorf("%w: launch recovery identity", ErrInput)
	}
	id, err := op.encode()
	if err != nil {
		return LaunchRecovery{}, err
	}
	return b.readLaunch(ctx, s, key, fingerprint, id)
}

func (b *Backend) readLaunch(
	ctx context.Context, s backend.Scope, key, fingerprint string, id resource.OperationID,
) (LaunchRecovery, error) {
	out := LaunchRecovery{Instances: map[int]resource.InstanceID{}, Operation: resource.Operation{
		ID: id, Action: resource.ActionRunInstances, OwnerID: s.Account, State: resource.OperationRunning,
	}}
	vms, err := b.visibleVMs(ctx, s)
	if err != nil {
		return LaunchRecovery{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return LaunchRecovery{}, err
	}
	finalized := 0
	var launchKey, launchFP string
	for _, vm := range vms {
		// A different finalized launch needs no config read.
		if key != "" && strings.Contains(vm.Tags, "vws.k.") &&
			!slices.Contains(strings.Split(vm.Tags, ";"), "vws.k."+key[:24]) {
			continue
		}
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		if key != "" && !strings.Contains(cfg.Description, " key="+key+" ") {
			continue
		}
		marker, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		if !found || marker.Account != s.Account {
			continue
		}
		op, err := newLaunchOperation(b.cluster, marker.Key)
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		candidate, err := op.encode()
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		if candidate != id || key != "" && marker.Key != key {
			continue
		}
		if fingerprint != "" && marker.Fingerprint != fingerprint {
			return LaunchRecovery{}, resource.IdempotencyMismatch()
		}
		if out.Count != 0 && (out.Count != marker.Count || launchKey != marker.Key || launchFP != marker.Fingerprint) {
			return LaunchRecovery{}, launchUnavailable(fmt.Errorf("inconsistent launch markers"))
		}
		if _, duplicate := out.Instances[marker.Index]; duplicate {
			return LaunchRecovery{}, launchUnavailable(fmt.Errorf("duplicate launch index"))
		}
		launchKey, launchFP, out.Count = marker.Key, marker.Fingerprint, marker.Count
		out.Reservation, err = ids.Reservation(marker.Key)
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		instance, _, err := ids.Instance(VM{UUID: marker.UUID})
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		out.Instances[marker.Index] = instance
		tags := strings.Split(cfg.Tags, ";")
		expected, err := LaunchMarkerTags(marker, out.Reservation)
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		if slices.Contains(tags, LaunchFailureTag) {
			out.Operation.State = resource.OperationFailed
			out.Operation.Error = resource.Conflict(resource.KindInstance, instance.String(), "launch finalization failed")
		}
		if cfg.Lock == "" && configUUID(cfg) == marker.UUID &&
			!slices.ContainsFunc(expected, func(tag string) bool { return !slices.Contains(tags, tag) }) {
			finalized++
		}
	}
	if out.Count == 0 {
		return LaunchRecovery{}, resource.NotFound(resource.KindOperation, id.String())
	}
	for index := 0; index < out.Count; index++ {
		if instance, exists := out.Instances[index]; exists {
			out.Operation.Targets = append(out.Operation.Targets, instance.Ref())
		}
	}
	if finalized == out.Count && out.Operation.State != resource.OperationFailed {
		out.Operation.State = resource.OperationSucceeded
	}
	return out, nil
}

func launchUnavailable(err error) error {
	return (&resource.Error{Code: resource.CodeUnavailable, Message: "Proxmox launch recovery unavailable"}).WithCause(err)
}
