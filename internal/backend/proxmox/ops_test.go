package proxmox

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestOperationIDGolden(t *testing.T) {
	instance, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newLaunchOperation("test", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op   operationID
		want string
	}{
		{launch, "op-compute-0301c8ca477577561646cd14140350d76f8d5c30"},
		{
			taskOperation{
				node: nodeHash("pve1"), pid: 0x123456, starttime: 0x6553f100,
				action: resource.ActionStopInstances, instance: instance,
			},
			"op-compute-012bb91234566553f100020123456789abcdef00",
		},
		{
			syncOperation{
				action: resource.ActionCreateTags, kind: resource.KindInstance,
				local: "0123456789abcdef0", keyHash: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			"op-compute-0218010123456789abcdef000102030405060708",
		},
	} {
		got, err := tc.op.encode()
		if err != nil || got.String() != tc.want {
			t.Fatalf("encode = %s, %v; want %s", got, err, tc.want)
		}
		decoded, err := decodeOperation(got)
		if err != nil || decoded != tc.op {
			t.Fatalf("decode = %+v, %v; want %+v", decoded, err, tc.op)
		}
	}
}

func TestOperationIDRefusesInvalid(t *testing.T) {
	a := "01abcd1234566553f100020123456789abcdef00"
	b := "0218010123456789abcdef000102030405060708"
	for _, tc := range []struct {
		name    string
		service resource.Service
		local   string
	}{
		{"wrong service", resource.ServiceStorage, a},
		{"short", resource.ServiceCompute, a[:38]},
		{"long", resource.ServiceCompute, a + "00"},
		{"uppercase", resource.ServiceCompute, strings.ToUpper(a)},
		{"non hex", resource.ServiceCompute, a[:39] + "g"},
		{"version", resource.ServiceCompute, "04" + a[2:]},
		{"launch action", resource.ServiceCompute, "03ff" + a[4:]},
		{"task action", resource.ServiceCompute, a[:20] + "ff" + a[22:]},
		{"task pad", resource.ServiceCompute, a[:39] + "1"},
		{"sync action", resource.ServiceCompute, b[:2] + "ff" + b[4:]},
		{"sync kind", resource.ServiceCompute, b[:4] + "ff" + b[6:]},
		{"sync pad", resource.ServiceCompute, b[:23] + "1" + b[24:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := resource.NewOperationID(tc.service, tc.local)
			if err == nil {
				_, err = decodeOperation(id)
			}
			if err == nil {
				t.Fatal("invalid operation accepted")
			}
		})
	}
	for _, parts := range [][2]string{
		{"", strings.Repeat("a", 64)},
		{"test\x00other", strings.Repeat("a", 64)},
		{"test", "short"},
		{"test", strings.Repeat("A", 64)},
	} {
		if _, err := newLaunchOperation(parts[0], parts[1]); !errors.Is(err, ErrInput) {
			t.Fatalf("launch inputs %q: %v", parts, err)
		}
	}
	instance, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	shortInstance, err := resource.Parse[resource.InstanceID]("i-000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		op   operationID
	}{
		{"task oversized pid", taskOperation{pid: 0x1000000, action: resource.ActionStopInstances, instance: instance}},
		{"task unknown action", taskOperation{action: 0xff, instance: instance}},
		{"task negative action", taskOperation{action: -1, instance: instance}},
		{"task oversized action", taskOperation{action: 0x1001, instance: shortInstance}},
		{"task short instance", taskOperation{action: resource.ActionStopInstances, instance: shortInstance}},
		{"task empty instance", taskOperation{action: resource.ActionStopInstances}},
		{"sync oversized action", syncOperation{action: 0x1001, kind: resource.KindInstance, local: "000000000000000"}},
		{"sync unknown action", syncOperation{action: 0xff, kind: resource.KindInstance, local: "0123456789abcdef0"}},
		{"sync negative action", syncOperation{action: -1, kind: resource.KindInstance, local: "0123456789abcdef0"}},
		{"sync unknown kind", syncOperation{action: resource.ActionCreateTags, kind: 0xff, local: "0123456789abcdef0"}},
		{"sync oversized kind", syncOperation{action: resource.ActionCreateTags, kind: 0x1001, local: "000000000000000"}},
		{"sync negative kind", syncOperation{action: resource.ActionCreateTags, kind: -1, local: "0123456789abcdef0"}},
		{"sync short target", syncOperation{
			action: resource.ActionCreateTags, kind: resource.KindInstance,
			local: "0123456789abcde",
		}},
		{"sync long target", syncOperation{
			action: resource.ActionCreateTags, kind: resource.KindInstance,
			local: "0123456789abcdef012",
		}},
		{"sync uppercase target", syncOperation{
			action: resource.ActionCreateTags, kind: resource.KindInstance,
			local: "0123456789ABCDEF0",
		}},
		{"sync nonhex target", syncOperation{
			action: resource.ActionCreateTags, kind: resource.KindInstance,
			local: "0123456789abcdefg",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := tc.op.encode()
			if !errors.Is(err, ErrInput) {
				t.Fatalf("encode %+v = %s, %v; want ErrInput", tc.op, id, err)
			}
		})
	}
}

func FuzzOperationIDRoundTrip(f *testing.F) {
	f.Add(uint16(0xabcd), uint32(0x123456), uint32(1700000000), byte(2), byte(1),
		uint64(0), byte(0), uint64(0x0102030405060708))
	f.Add(uint16(0xffff), uint32(0xffffff), uint32(0xffffffff), byte(29), byte(13),
		^uint64(0), byte(15), uint64(0))
	f.Add(uint16(0), uint32(0), uint32(0), byte(1), byte(1), uint64(1), byte(1), ^uint64(0))
	f.Fuzz(func(t *testing.T, node uint16, pid, start uint32, action, kind byte, value uint64, last byte, key uint64) {
		if pid > 0xffffff || last > 15 || resource.Action(action).String() == "" || resource.Kind(kind).String() == "" {
			return
		}
		var raw [9]byte
		for i := range 8 {
			raw[i] = byte(value >> (56 - 8*i))
		}
		raw[8] = last << 4
		local := hex.EncodeToString(raw[:])[:17]
		var keyHash [8]byte
		binary.BigEndian.PutUint64(keyHash[:], key)
		instance, err := resource.Parse[resource.InstanceID]("i-" + local)
		if err != nil {
			t.Fatal(err)
		}
		ops := []operationID{
			launchOperation{keyHash: [18]byte{byte(node), byte(pid), byte(start), action, kind, byte(key)}},
			taskOperation{node: node, pid: pid, starttime: start, action: resource.Action(action), instance: instance},
			syncOperation{
				action: resource.Action(action), kind: resource.Kind(kind), local: local,
				keyHash: keyHash,
			},
		}
		for _, op := range ops {
			id, err := op.encode()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := resource.Parse[resource.OperationID](id.String())
			if err != nil || parsed != id {
				t.Fatalf("resource parse = %s, %v; want %s", parsed, err, id)
			}
			got, err := decodeOperation(id)
			if err != nil || got != op {
				t.Fatalf("round trip = %+v, %v; want %+v", got, err, op)
			}
		}
	})
}
