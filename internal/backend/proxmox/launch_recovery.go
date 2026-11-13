package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

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
	vms = slices.DeleteFunc(vms, func(vm inventoryVM) bool {
		return key != "" && strings.Contains(vm.Tags, "vws.k.") &&
			!slices.Contains(strings.Split(vm.Tags, ";"), "vws.k."+key[:24])
	})
	configs := make([]struct {
		config pveclient.VMConfig
		err    error
	}, len(vms))
	slots := make(chan struct{}, 8)
	var reads sync.WaitGroup
	for i, vm := range vms {
		slots <- struct{}{}
		reads.Go(func() {
			defer func() { <-slots }()
			configs[i].config, configs[i].err = b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		})
	}
	reads.Wait()
	for i, vm := range vms {
		cfg := configs[i].config
		if configs[i].err != nil {
			return LaunchRecovery{}, launchUnavailable(configs[i].err)
		}
		if !b.launchDescriptionMatches(cfg.Description, id) {
			if strings.Contains(cfg.Description, launchMarkerPrefix) {
				if _, _, err := ReadLaunchMarker(cfg.Description); err != nil {
					slog.WarnContext(ctx, "skipping undecodable unrelated launch marker", slog.Int("vmid", vm.VMID))
				}
			}
			continue
		}
		marker, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil {
			return LaunchRecovery{}, launchUnavailable(err)
		}
		if !found || marker.Account != s.Account {
			continue
		}
		if key != "" && marker.Key != key {
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

func (b *Backend) launchDescriptionMatches(description string, id resource.OperationID) bool {
	for line := range strings.SplitSeq(description, "\n") {
		if !strings.HasPrefix(line, launchMarkerPrefix) {
			continue
		}
		for field := range strings.FieldsSeq(line) {
			key, found := strings.CutPrefix(field, "key=")
			if !found || !launchHex(key, 64) {
				continue
			}
			op, err := newLaunchOperation(b.cluster, key)
			if err == nil {
				candidate, err := op.encode()
				if err == nil && candidate == id {
					return true
				}
			}
		}
	}
	return false
}

func launchUnavailable(err error) error {
	return (&resource.Error{Code: resource.CodeUnavailable, Message: "Proxmox launch recovery unavailable"}).WithCause(err)
}
