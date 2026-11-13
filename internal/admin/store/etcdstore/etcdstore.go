// Package etcdstore is the admin registry Backend on etcd. It is the only
// package that sees etcd types. A record's version is its etcd mod revision,
// and every conditional write is one transaction comparing it.
package etcdstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

// CallTimeout bounds each etcd call. The client retries transient failures
// of a call within it.
const CallTimeout = 5 * time.Second

// Store keeps records under store.Prefix.
type Store struct {
	kv clientv3.KV
}

// New returns a Store over kv, usually a *clientv3.Client.
func New(kv clientv3.KV) *Store { return &Store{kv: kv} }

// Create puts key only if it has never been created or was deleted.
func (s *Store) Create(ctx context.Context, key string, value []byte) (store.Version, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	k := store.Prefix + key
	resp, err := s.kv.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(k), "=", 0)).
		Then(clientv3.OpPut(k, string(value))).
		Commit()
	if err != nil {
		return 0, fmt.Errorf("etcd create %s: %w", k, err)
	}
	if !resp.Succeeded {
		return 0, store.ErrExists
	}
	return store.Version(resp.Header.Revision), nil
}

// Get reads key.
func (s *Store) Get(ctx context.Context, key string) (store.Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	k := store.Prefix + key
	resp, err := s.kv.Get(ctx, k)
	if err != nil {
		return store.Entry{}, fmt.Errorf("etcd get %s: %w", k, err)
	}
	if len(resp.Kvs) == 0 {
		return store.Entry{}, store.ErrNotFound
	}
	kv := resp.Kvs[0]
	return store.Entry{Key: key, Value: kv.Value, Version: store.Version(kv.ModRevision)}, nil
}

// List reads every key under prefix in key order.
func (s *Store) List(ctx context.Context, prefix string) ([]store.Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	p := store.Prefix + prefix
	resp, err := s.kv.Get(ctx, p, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
	if err != nil {
		return nil, fmt.Errorf("etcd list %s: %w", p, err)
	}
	out := make([]store.Entry, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		out = append(out, store.Entry{
			Key:     string(kv.Key[len(store.Prefix):]),
			Value:   kv.Value,
			Version: store.Version(kv.ModRevision),
		})
	}
	return out, nil
}

// Update puts key if its mod revision is expected.
func (s *Store) Update(ctx context.Context, key string, value []byte, expected store.Version) (store.Version, error) {
	return s.ifAt(ctx, key, expected, clientv3.OpPut(store.Prefix+key, string(value)))
}

// Delete removes key if its mod revision is expected.
func (s *Store) Delete(ctx context.Context, key string, expected store.Version) error {
	if name, ok := strings.CutPrefix(key, "regions/"); ok {
		ctx, cancel := context.WithTimeout(ctx, CallTimeout)
		defer cancel()
		k := store.Prefix + key
		claims := store.Prefix + "project-pools/" + name + "/"
		resp, err := s.kv.Txn(ctx).
			If(
				clientv3.Compare(clientv3.CreateRevision(k), ">", 0),
				clientv3.Compare(clientv3.ModRevision(k), "=", int64(expected)),
				clientv3.Compare(clientv3.CreateRevision(claims), "=", 0).WithPrefix(),
			).
			Then(clientv3.OpDelete(k)).
			Else(clientv3.OpGet(k)).
			Commit()
		if err != nil {
			return fmt.Errorf("etcd delete region %s: %w", k, err)
		}
		if resp.Succeeded {
			return nil
		}
		current := resp.Responses[0].GetResponseRange().Kvs
		if len(current) == 0 {
			return store.ErrNotFound
		}
		if current[0].ModRevision != int64(expected) {
			return store.ErrConflict
		}
		return store.ErrRegionInUse
	}
	_, err := s.ifAt(ctx, key, expected, clientv3.OpDelete(store.Prefix+key))
	return err
}

// Swap compares the project and pool claims in the same transaction as their writes.
func (s *Store) Swap(ctx context.Context, checks, puts []store.Entry, deletes []string) (store.Version, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	conditions := make([]clientv3.Cmp, 0, len(checks))
	for _, e := range checks {
		conditions = append(conditions, clientv3.Compare(clientv3.ModRevision(store.Prefix+e.Key), "=", int64(e.Version)))
	}
	ops := make([]clientv3.Op, 0, len(puts)+len(deletes))
	for _, e := range puts {
		ops = append(ops, clientv3.OpPut(store.Prefix+e.Key, string(e.Value)))
	}
	for _, key := range deletes {
		ops = append(ops, clientv3.OpDelete(store.Prefix+key))
	}
	resp, err := s.kv.Txn(ctx).If(conditions...).Then(ops...).Commit()
	if err != nil {
		return 0, fmt.Errorf("etcd swap project mapping: %w", err)
	}
	if !resp.Succeeded {
		return 0, store.ErrConflict
	}
	return store.Version(resp.Header.Revision), nil
}

// ifAt runs op when key is at expected. On a miss the same transaction reads
// key, which tells a missing key from a changed one.
func (s *Store) ifAt(ctx context.Context, key string, expected store.Version, op clientv3.Op) (store.Version, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	k := store.Prefix + key
	resp, err := s.kv.Txn(ctx).
		If(
			clientv3.Compare(clientv3.CreateRevision(k), ">", 0),
			clientv3.Compare(clientv3.ModRevision(k), "=", int64(expected)),
		).
		Then(op).
		Else(clientv3.OpGet(k, clientv3.WithCountOnly())).
		Commit()
	if err != nil {
		return 0, fmt.Errorf("etcd write %s: %w", k, err)
	}
	if resp.Succeeded {
		return store.Version(resp.Header.Revision), nil
	}
	if resp.Responses[0].GetResponseRange().Count == 0 {
		return 0, store.ErrNotFound
	}
	return 0, store.ErrConflict
}
