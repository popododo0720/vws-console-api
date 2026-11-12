package store

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// Memory is a Backend held in memory, for tests.
type Memory struct {
	mu      sync.Mutex
	rev     Version
	entries map[string]Entry
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory { return &Memory{entries: map[string]Entry{}} }

// Create stores value under a new key.
func (m *Memory) Create(_ context.Context, key string, value []byte) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key]; ok {
		return 0, ErrExists
	}
	return m.put(key, value), nil
}

// Get reads key.
func (m *Memory) Get(_ context.Context, key string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return clone(e), nil
}

// List reads every key under prefix in key order.
func (m *Memory) List(_ context.Context, prefix string) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for k, e := range m.entries {
		if strings.HasPrefix(k, prefix) {
			out = append(out, clone(e))
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// Update replaces key if it is at expected.
func (m *Memory) Update(_ context.Context, key string, value []byte, expected Version) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(key, expected); err != nil {
		return 0, err
	}
	return m.put(key, value), nil
}

// Delete removes key if it is at expected.
func (m *Memory) Delete(_ context.Context, key string, expected Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(key, expected); err != nil {
		return err
	}
	delete(m.entries, key)
	return nil
}

// Swap compares all keys and changes them under one lock and revision.
func (m *Memory) Swap(ctx context.Context, checks, puts []Entry, deletes []string) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	for _, e := range checks {
		if m.entries[e.Key].Version != e.Version {
			return 0, ErrConflict
		}
	}
	m.rev++
	for _, e := range puts {
		m.entries[e.Key] = Entry{Key: e.Key, Value: slices.Clone(e.Value), Version: m.rev}
	}
	for _, key := range deletes {
		delete(m.entries, key)
	}
	return m.rev, nil
}

func (m *Memory) check(key string, expected Version) error {
	e, ok := m.entries[key]
	switch {
	case !ok:
		return ErrNotFound
	case e.Version != expected:
		return ErrConflict
	default:
		return nil
	}
}

func (m *Memory) put(key string, value []byte) Version {
	m.rev++
	m.entries[key] = Entry{Key: key, Value: slices.Clone(value), Version: m.rev}
	return m.rev
}

func clone(e Entry) Entry {
	e.Value = slices.Clone(e.Value)
	return e
}
