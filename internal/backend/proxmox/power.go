package proxmox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// StartInstances starts stopped VMs; earlier submissions survive a later target's failure.
func (b *Backend) StartInstances(ctx context.Context, m backend.Mutation,
	req resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstPowerID(req.IDs)); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return b.changePower(ctx, m.Scope, m.Key, req.IDs, resource.ActionStartInstances, "start")
}

// StopInstances shuts down VMs, or forces a stop; earlier submissions survive a later target's failure.
func (b *Backend) StopInstances(ctx context.Context, m backend.Mutation,
	req resource.StopInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstPowerID(req.IDs)); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	action := "shutdown"
	if req.Force {
		action = "stop"
	}
	return b.changePower(ctx, m.Scope, m.Key, req.IDs, resource.ActionStopInstances, action)
}

// RebootInstances reboots running VMs; earlier submissions survive a later target's failure.
func (b *Backend) RebootInstances(ctx context.Context, m backend.Mutation,
	req resource.RebootInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstPowerID(req.IDs)); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return b.changePower(ctx, m.Scope, m.Key, req.IDs, resource.ActionRebootInstances, "reboot")
}

// TerminateInstances destroys unprotected VMs; earlier submissions survive a later target's failure.
func (b *Backend) TerminateInstances(ctx context.Context, m backend.Mutation,
	req resource.TerminateInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstPowerID(req.IDs)); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return b.changePower(ctx, m.Scope, m.Key, req.IDs, resource.ActionTerminateInstances, "destroy")
}

func firstPowerID(ids []resource.InstanceID) resource.InstanceID {
	if len(ids) == 0 {
		return resource.InstanceID{}
	}
	return ids[0]
}

func powerUnavailable(err error) error {
	return (&resource.Error{Code: resource.CodeUnavailable, Message: "Proxmox power operation unavailable"}).WithCause(err)
}

func (b *Backend) changePower(ctx context.Context, s backend.Scope, key string,
	ids []resource.InstanceID, action resource.Action, verb string,
) (resource.Accepted[resource.InstanceStateChange], error) {
	var acc resource.Accepted[resource.InstanceStateChange]
	vms := make([]inventoryVM, len(ids))
	states := make([]resource.InstanceState, len(ids))
	for i, id := range ids {
		vm, err := b.vmForMutation(ctx, s, id)
		if err != nil {
			return acc, err
		}
		vms[i] = vm
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			return acc, powerUnavailable(err)
		}
		if verb == "destroy" && cfg.Protection == 1 {
			return acc, &resource.Error{
				Code: resource.CodeConflict, Kind: resource.KindInstance,
				ID: id.String(), Field: "protection", Message: "The instance is protected from termination.",
			}
		}
		if verb == "destroy" {
			for disk, drive := range cfg.Drives {
				if disk == "scsi0" || diskDevice(disk) == "" || option(drive, "media") == "cdrom" ||
					strings.Contains(drive, "cloudinit") {
					continue
				}
				serial := option(drive, "serial")
				if len(serial) < 8 || !slices.Contains(strings.Split(cfg.Tags, ";"), "vws.dot."+serial[:8]) {
					return acc, resource.Unsupported(action.String(), "retained disks require holder support")
				}
			}
		}
		if cfg.Lock != "" && (verb != "destroy" || cfg.Lock != "destroy") {
			return acc, resource.Conflict(resource.KindInstance, id.String(), "instance is locked")
		}
		states[i] = resource.InstanceStopped
		if vm.Status == "running" {
			states[i] = resource.InstanceRunning
		}
		if verb == "reboot" && states[i] != resource.InstanceRunning {
			return acc, resource.Conflict(resource.KindInstance, id.String(), "instance is not running")
		}
	}
	for i, vm := range vms {
		id, previous := ids[i], states[i]
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		rows, err := b.client.OwnTasks(ctx, vm.Node, url.Values{
			"vmid": {strconv.Itoa(vm.VMID)}, "typefilter": {"qm" + verb}, "limit": {"1000"},
		})
		if err != nil {
			return acc, powerUnavailable(err)
		}
		atTarget := verb == "start" && previous == resource.InstanceRunning ||
			(verb == "shutdown" || verb == "stop") && previous == resource.InstanceStopped
		var op resource.Operation
		switch {
		case len(rows) != 0 && (rows[0].Status == "RUNNING" || atTarget && rows[0].Status == "OK"):
			op, err = b.powerTaskOperation(ctx, s, id, action, rows[0])
		case atTarget:
			sum := sha256.Sum256([]byte(key))
			op.ID, err = (syncOperation{
				action: action, kind: resource.KindInstance,
				local: strings.TrimPrefix(id.String(), "i-"), keyHash: [8]byte(sum[:8]),
			}).encode()
			op.Action, op.OwnerID, op.State = action, s.Account, resource.OperationSucceeded
		default:
			if verb == "destroy" && previous == resource.InstanceRunning {
				var upid string
				upid, err = b.client.Power(ctx, target, "stop", 0)
				if err == nil {
					err = b.client.WaitTask(ctx, pveclient.Task{Node: vm.Node, UPID: upid}, pveclient.StopWait)
				}
				if err != nil {
					return acc, powerUnavailable(err)
				}
			}
			timeout := b.cfg.ShutdownTimeout
			if timeout <= 0 {
				timeout = 120
			}
			var upid string
			upid, err = b.client.Power(ctx, target, verb, timeout)
			if err == nil {
				parts := strings.Split(upid, ":")
				if len(parts) != 9 || parts[0] != "UPID" || parts[1] != vm.Node {
					return acc, resource.Internal(fmt.Errorf("proxmox: invalid power task ID"))
				}
				pid, pidErr := strconv.ParseUint(parts[2], 16, 24)
				start, startErr := strconv.ParseUint(parts[4], 16, 32)
				if pidErr != nil || startErr != nil {
					return acc, resource.Internal(fmt.Errorf("proxmox: invalid power task coordinates"))
				}
				op, err = b.powerTaskOperation(ctx, s, id, action, pveclient.TaskRow{
					UPID: upid, Node: vm.Node, PID: uint32(pid), StartTime: uint32(start),
				})
			}
		}
		if err != nil {
			return acc, powerUnavailable(err)
		}
		current := previous
		if !atTarget {
			current = map[string]resource.InstanceState{
				"start": resource.InstancePending, "shutdown": resource.InstanceStopping,
				"stop": resource.InstanceStopping, "reboot": resource.InstanceRunning, "destroy": resource.InstanceShuttingDown,
			}[verb]
		}
		acc.Items = append(acc.Items, resource.InstanceStateChange{
			ID: id, OwnerID: s.Account, Previous: previous, Current: current,
		})
		if i == 0 {
			acc.Operation = op
			acc.Operation.Targets = nil
		}
		acc.Operation.Targets = append(acc.Operation.Targets, id.Ref())
	}
	return acc, nil
}

func (b *Backend) powerTaskOperation(ctx context.Context, s backend.Scope, id resource.InstanceID,
	action resource.Action, row pveclient.TaskRow,
) (resource.Operation, error) {
	opID, err := (taskOperation{
		node: nodeHash(row.Node), pid: row.PID,
		starttime: row.StartTime, action: action, instance: id,
	}).encode()
	if err != nil {
		return resource.Operation{}, err
	}
	status, err := b.client.ReadTask(ctx, pveclient.Task{Node: row.Node, UPID: row.UPID})
	if err != nil {
		return resource.Operation{}, err
	}
	op := resource.Operation{
		ID: opID, Action: action, OwnerID: s.Account,
		Targets: []resource.Ref{id.Ref()}, State: resource.OperationRunning,
		CreateTime: time.Unix(int64(row.StartTime), 0).UTC(),
	}
	op.UpdateTime = time.Unix(max(int64(row.StartTime), row.EndTime), 0).UTC()
	if status.Status == "stopped" {
		op.State = resource.OperationSucceeded
		if status.ExitStatus != "OK" {
			op.State = resource.OperationFailed
			op.Error = &resource.Error{Code: resource.CodeConflict, Message: b.client.Redact(status.ExitStatus)}
		}
	}
	return op, nil
}

// GetOperation recovers task coordinates without process-local operation state.
func (b *Backend) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	missing := resource.NotFound(resource.KindOperation, id.String())
	decoded, err := decodeOperation(id)
	if err != nil {
		return resource.Operation{}, missing
	}
	if _, ok := decoded.(launchOperation); ok {
		recovered, err := b.readLaunch(ctx, s, "", "", id)
		return recovered.Operation, err
	}
	if sync, ok := decoded.(syncOperation); ok {
		if sync.action == resource.ActionCreateSnapshot && sync.kind == resource.KindSnapshot {
			return b.snapshotCreateOperation(ctx, s, id, sync)
		}
		if sync.action == resource.ActionCreateTags || sync.action == resource.ActionDeleteTags {
			return b.tagOperation(ctx, s, id)
		}
		if sync.kind == resource.KindVolume {
			target, err := resource.Parse[resource.VolumeID]("vol-" + sync.local)
			if err != nil {
				return resource.Operation{}, missing
			}
			if _, err := b.volumeForMutation(ctx, s, target); err != nil {
				return resource.Operation{}, err
			}
			return resource.Operation{
				ID: id, Action: sync.action, OwnerID: s.Account,
				Targets: []resource.Ref{target.Ref()}, State: resource.OperationSucceeded,
			}, nil
		}
		target, err := resource.Parse[resource.InstanceID]("i-" + sync.local)
		if err != nil || sync.kind != resource.KindInstance {
			return resource.Operation{}, missing
		}
		if _, err := b.vmForMutation(ctx, s, target); err != nil {
			return resource.Operation{}, missing
		}
		return resource.Operation{
			ID: id, Action: sync.action, OwnerID: s.Account,
			Targets: []resource.Ref{target.Ref()}, State: resource.OperationSucceeded,
		}, nil
	}
	task, ok := decoded.(taskOperation)
	if !ok {
		return resource.Operation{}, missing
	}
	nodes, err := b.client.Nodes(ctx)
	if err != nil {
		return resource.Operation{}, powerUnavailable(err)
	}
	for _, node := range nodes {
		if nodeHash(node.Node) != task.node {
			continue
		}
		q := url.Values{
			"since": {strconv.FormatUint(uint64(task.starttime), 10)},
			"until": {strconv.FormatUint(uint64(task.starttime), 10)}, "limit": {"1000"},
		}
		rows, err := b.client.OwnTasks(ctx, node.Node, q)
		if err != nil {
			return resource.Operation{}, powerUnavailable(err)
		}
		for _, row := range rows {
			types := map[resource.Action][]string{
				resource.ActionStartInstances: {"qmstart"}, resource.ActionStopInstances: {"qmshutdown", "qmstop"},
				resource.ActionRebootInstances: {"qmreboot"}, resource.ActionTerminateInstances: {"qmdestroy"},
			}
			if row.PID != task.pid || row.StartTime != task.starttime || !slices.Contains(types[task.action], row.Type) {
				continue
			}
			vms, err := b.client.ClusterResources(ctx, pveclient.ResourceVM)
			if err != nil {
				return resource.Operation{}, powerUnavailable(err)
			}
			for _, vm := range vms {
				if vm.Type != "qemu" || strconv.Itoa(vm.VMID) != row.ID {
					continue
				}
				guarded, err := b.vmForMutation(ctx, s, task.instance)
				if err != nil || guarded.VMID != vm.VMID {
					return resource.Operation{}, missing
				}
			}
			return b.powerTaskOperation(ctx, s, task.instance, task.action, row)
		}
	}
	return resource.Operation{}, missing
}
