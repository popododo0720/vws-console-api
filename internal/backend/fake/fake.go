// Package fake is an in-memory backend set. It is the simulated service, not
// state of the API process: a new API process pointed at the same fake sees
// the same records. Time moves only when a call observes the clock, so tests
// stay deterministic and the fake starts no goroutines.
package fake

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Options configures a world. Zero values use the wall clock, no settle
// delay, and crypto/rand. Images seeds the compute image store; the catalog
// image is always present. Buckets seeds storage with records another path
// wrote, including names the current create rule refuses (#511).
type Options struct {
	Now     func() time.Time
	Latency time.Duration
	Entropy io.Reader
	Images  []resource.Image
	Buckets []resource.Bucket
}

// World is one account-aware simulation of compute, storage, and network.
type World struct {
	now     func() time.Time
	latency time.Duration
	entropy io.Reader

	mu    sync.Mutex
	idem  map[string]idemRecord
	ops   map[string]*opRecord
	inst  map[resource.InstanceID]*resource.Instance
	sub   map[resource.SubnetID]*resource.Subnet
	vpc   map[resource.VpcID]*resource.Vpc
	vol   map[resource.VolumeID]*resource.Volume
	sg    map[resource.SecurityGroupID]*resource.SecurityGroup
	key   map[resource.KeyPairID]*resource.KeyPair
	addr  map[resource.AddressID]*resource.Address
	snap  map[resource.SnapshotID]*resource.Snapshot
	img   map[resource.ImageID]*resource.Image
	buck  map[resource.BucketName]*resource.Bucket
	obj   map[string]*storedObject
	seqIP uint32
	// detached is when each volume was last detached from each instance
	// with a client token, for the DetachVolume record budget (#303).
	detached map[resource.InstanceID]map[resource.VolumeID]time.Time
}

type idemRecord struct {
	fingerprint string
	value       any
}

type opRecord struct {
	op      resource.Operation
	due     time.Time
	settled bool
	apply   func(now time.Time)
}

type storedObject struct {
	meta resource.Object
	body []byte
}

// New builds a world and the three service views over it.
func New(opt Options) *World {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Entropy == nil {
		opt.Entropy = rand.Reader
	}
	world := &World{
		now:      opt.Now,
		latency:  opt.Latency,
		entropy:  opt.Entropy,
		idem:     map[string]idemRecord{},
		detached: map[resource.InstanceID]map[resource.VolumeID]time.Time{},
		ops:      map[string]*opRecord{},
		inst:     map[resource.InstanceID]*resource.Instance{},
		sub:      map[resource.SubnetID]*resource.Subnet{},
		vpc:      map[resource.VpcID]*resource.Vpc{},
		vol:      map[resource.VolumeID]*resource.Volume{},
		sg:       map[resource.SecurityGroupID]*resource.SecurityGroup{},
		key:      map[resource.KeyPairID]*resource.KeyPair{},
		addr:     map[resource.AddressID]*resource.Address{},
		snap:     map[resource.SnapshotID]*resource.Snapshot{},
		img:      map[resource.ImageID]*resource.Image{},
		buck:     map[resource.BucketName]*resource.Bucket{},
		obj:      map[string]*storedObject{},
	}
	for _, img := range opt.Images {
		world.img[img.ID] = &img
	}
	for _, bucket := range opt.Buckets {
		world.buck[bucket.Name] = &bucket
	}
	return world
}

// Set returns the three clients.
func (w *World) Set() backend.Set {
	return backend.Set{Compute: compute{w}, Storage: storage{w}, Network: network{w}}
}

func (w *World) settle(now time.Time) {
	for _, op := range w.ops {
		if op.settled || now.Before(op.due) {
			continue
		}
		op.apply(now)
		op.op.State = resource.OperationSucceeded
		op.op.UpdateTime = now.UTC()
		op.settled = true
	}
}

// replay returns the recorded result for key. A record of another type is
// an internal error, not a zero value.
func replay[T any](w *World, key, fingerprint string) (T, bool, error) {
	var zero T
	rec, ok := w.idem[key]
	if !ok {
		return zero, false, nil
	}
	if rec.fingerprint != fingerprint {
		return zero, false, resource.IdempotencyMismatch()
	}
	v, ok := rec.value.(T)
	if !ok {
		return zero, false, resource.Internal(fmt.Errorf("idempotency record %s holds %T", key, rec.value))
	}
	return v, true, nil
}

func (w *World) finish(key, fingerprint string, value any) {
	w.idem[key] = idemRecord{fingerprint: fingerprint, value: value}
}

func (w *World) newOp(account resource.AccountID, svc resource.Service, action resource.Action, targets []resource.Ref, apply func(time.Time)) (resource.Operation, error) {
	var raw [8]byte
	if _, err := io.ReadFull(w.entropy, raw[:]); err != nil {
		return resource.Operation{}, resource.Internal(err)
	}
	local := hexEncode(raw[:])
	id, err := resource.NewOperationID(svc, local)
	if err != nil {
		return resource.Operation{}, err
	}
	if _, exists := w.ops[id.String()]; exists {
		return resource.Operation{}, resource.Internal(errors.New("identifier collision"))
	}
	now := w.now().UTC()
	op := resource.Operation{
		ID:         id,
		Action:     action,
		State:      resource.OperationRunning,
		OwnerID:    account,
		Targets:    targets,
		CreateTime: now,
		UpdateTime: now,
	}
	w.ops[id.String()] = &opRecord{op: op, due: now.Add(w.latency), apply: apply}
	return op, nil
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

func (w *World) getOp(s backend.Scope, id resource.OperationID, svc resource.Service) (resource.Operation, error) {
	w.settle(w.now())
	if id.Service() != svc {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	rec, ok := w.ops[id.String()]
	if !ok {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	if !w.opOwned(s.Account, rec.op) {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	return rec.op, nil
}

func (w *World) opOwned(account resource.AccountID, op resource.Operation) bool {
	return !account.IsZero() && op.OwnerID == account
}

func page[T any](items []T, q resource.PageRequest) (resource.Page[T], error) {
	if q.Size < 1 {
		return resource.Page[T]{}, resource.Invalid("pageSize", "must be from 1 to 100")
	}
	start := 0
	if q.Token != "" {
		found := false
		for i, item := range items {
			if identity(item) == q.Token {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return resource.Page[T]{}, resource.Invalid("pageToken", "unknown")
		}
	}
	if start > len(items) {
		start = len(items)
	}
	end := start + q.Size
	next := ""
	if end < len(items) {
		next = identity(items[end-1])
	} else {
		end = len(items)
	}
	out := append([]T(nil), items[start:end]...)
	return resource.Page[T]{Items: out, NextToken: next}, nil
}

// Sequence is a deterministic entropy source for tests. Bytes are the
// big-endian form of 1, 2, 3, and so on, so an 8-byte draw cannot repeat.
type Sequence struct {
	n   uint64
	buf [8]byte
	off int
}

// Read fills p with deterministic bytes.
func (s *Sequence) Read(p []byte) (int, error) {
	for i := range p {
		if s.off == 0 || s.off == len(s.buf) {
			s.n++
			binary.BigEndian.PutUint64(s.buf[:], s.n)
			s.off = 0
		}
		p[i] = s.buf[s.off]
		s.off++
	}
	return len(p), nil
}

func identity(v any) string {
	if o, ok := v.(resource.Owned); ok {
		return o.Identity()
	}
	return ""
}
