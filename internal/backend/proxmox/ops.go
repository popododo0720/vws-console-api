package proxmox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type operationID interface {
	encode() (resource.OperationID, error)
}

type taskOperation struct {
	node      uint16
	pid       uint32
	starttime uint32
	action    resource.Action
	instance  resource.InstanceID
}

type syncOperation struct {
	action  resource.Action
	kind    resource.Kind
	local   string
	keyHash [8]byte
}

type launchOperation struct {
	keyHash [18]byte
}

func newLaunchOperation(cluster, key string) (launchOperation, error) {
	if err := checkPart(cluster); err != nil || !launchHex(key, 64) {
		return launchOperation{}, fmt.Errorf("%w: launch operation cluster or key", ErrInput)
	}
	sum := sha256.Sum256([]byte("vws-pve-op-launch-v1\x00" + cluster + "\x00" + key))
	return launchOperation{keyHash: [18]byte(sum[:18])}, nil
}

func (op launchOperation) encode() (resource.OperationID, error) {
	return encodeOperation(fmt.Sprintf("03%02x%x", int(resource.ActionRunInstances), op.keyHash))
}

func nodeHash(name string) uint16 {
	sum := sha256.Sum256([]byte("vws-pve-op-node-v1\x00" + name))
	return binary.BigEndian.Uint16(sum[:2])
}

func (op taskOperation) encode() (resource.OperationID, error) {
	if op.pid > 0xffffff {
		return resource.OperationID{}, fmt.Errorf("%w: operation pid exceeds 24 bits", ErrInput)
	}
	if op.action < 0 || op.action > 0xff || op.action.String() == "" {
		return resource.OperationID{}, fmt.Errorf("%w: unknown or oversized operation action", ErrInput)
	}
	instance := strings.TrimPrefix(op.instance.String(), "i-")
	if !validOperationLocal(instance) {
		return resource.OperationID{}, fmt.Errorf("%w: operation instance must be 17 lowercase hex digits", ErrInput)
	}
	local := fmt.Sprintf("01%04x%06x%08x%02x%s0",
		op.node, op.pid, op.starttime, int(op.action), instance)
	return encodeOperation(local)
}

func (op syncOperation) encode() (resource.OperationID, error) {
	if op.action < 0 || op.action > 0xff || op.action.String() == "" {
		return resource.OperationID{}, fmt.Errorf("%w: unknown or oversized operation action", ErrInput)
	}
	if op.kind < 0 || op.kind > 0xff || op.kind.String() == "" {
		return resource.OperationID{}, fmt.Errorf("%w: unknown or oversized operation kind", ErrInput)
	}
	if !validOperationLocal(op.local) {
		return resource.OperationID{}, fmt.Errorf("%w: operation target must be 17 lowercase hex digits", ErrInput)
	}
	return encodeOperation(fmt.Sprintf("02%02x%02x%s0%x", int(op.action), int(op.kind), op.local, op.keyHash))
}

func validOperationLocal(local string) bool {
	return len(local) == idHexLen && strings.Trim(local, "0123456789abcdef") == ""
}

func encodeOperation(local string) (resource.OperationID, error) {
	id, err := resource.NewOperationID(resource.ServiceCompute, local)
	if err != nil {
		return resource.OperationID{}, fmt.Errorf("proxmox: encode operation: %w", err)
	}
	if _, err := decodeOperation(id); err != nil {
		return resource.OperationID{}, fmt.Errorf("proxmox: encode operation: %w", err)
	}
	return id, nil
}

func decodeOperation(id resource.OperationID) (operationID, error) {
	local := id.Local()
	if id.Service() != resource.ServiceCompute || len(local) != 40 || strings.ToLower(local) != local {
		return nil, fmt.Errorf("%w: operation service or local format", ErrInput)
	}
	raw, err := hex.DecodeString(local)
	if err != nil {
		return nil, fmt.Errorf("proxmox: decode operation hex: %w", err)
	}
	switch raw[0] {
	case 1:
		action := resource.Action(raw[10])
		if action.String() == "" || local[39] != '0' {
			return nil, fmt.Errorf("%w: operation action or instance pad", ErrInput)
		}
		instance, err := resource.Parse[resource.InstanceID]("i-" + local[22:39])
		if err != nil {
			return nil, fmt.Errorf("proxmox: decode operation instance: %w", err)
		}
		return taskOperation{
			node:      binary.BigEndian.Uint16(raw[1:3]),
			pid:       uint32(raw[3])<<16 | uint32(raw[4])<<8 | uint32(raw[5]),
			starttime: binary.BigEndian.Uint32(raw[6:10]), action: action, instance: instance,
		}, nil
	case 2:
		action, kind := resource.Action(raw[1]), resource.Kind(raw[2])
		if action.String() == "" || kind.String() == "" || local[23] != '0' {
			return nil, fmt.Errorf("%w: operation action, kind or target pad", ErrInput)
		}
		return syncOperation{
			action: action, kind: kind, local: local[6:23], keyHash: [8]byte(raw[12:20]),
		}, nil
	case 3:
		if resource.Action(raw[1]) != resource.ActionRunInstances {
			return nil, fmt.Errorf("%w: launch operation action", ErrInput)
		}
		return launchOperation{keyHash: [18]byte(raw[2:20])}, nil
	default:
		return nil, fmt.Errorf("%w: unknown operation version %02x", ErrInput, raw[0])
	}
}
