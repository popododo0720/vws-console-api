package launch

import (
	"context"
	"slices"
	"strconv"
	"sync"
)

// Memory is a Store in process memory, for tests. It counts writes, so a
// test can assert that a step that changes nothing writes nothing.
type Memory struct {
	mu      sync.Mutex
	records map[string]memoryEntry
	writes  int
	// failIn counts the writes left before fail is returned; fail is unset
	// when no failure is armed.
	failIn int
	fail   error
}

type memoryEntry struct {
	rec     Record
	version int
}

// Load returns the record for key.
func (m *Memory) Load(_ context.Context, key string) (Record, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.records[key]
	if !ok {
		return Record{}, "", false, nil
	}
	return clone(e.rec), strconv.Itoa(e.version), true, nil
}

// Create stores rec when its key has no record. Like the Kubernetes API, it
// refuses a cancelled context.
func (m *Memory) Create(ctx context.Context, rec Record) (string, error) { return m.put(ctx, rec, "") }

// Update stores rec when version is the stored version.
func (m *Memory) Update(ctx context.Context, rec Record, version string) (string, error) {
	return m.put(ctx, rec, version)
}

// put creates rec when version is empty and replaces the stored version otherwise.
func (m *Memory) put(ctx context.Context, rec Record, version string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeFail(ctx); err != nil {
		return "", err
	}
	e, ok := m.records[rec.Key]
	switch {
	case version == "" && ok:
		return "", ErrExists
	case version != "" && (!ok || strconv.Itoa(e.version) != version):
		return "", ErrConflict
	}
	if m.records == nil {
		m.records = map[string]memoryEntry{}
	}
	m.writes++
	m.records[rec.Key] = memoryEntry{rec: clone(rec), version: e.version + 1}
	return strconv.Itoa(e.version + 1), nil
}

// Writes is the number of successful creates and updates.
func (m *Memory) Writes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writes
}

// FailAfter lets n creates or updates through, then makes the next one
// return err and write nothing.
func (m *Memory) FailAfter(n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failIn, m.fail = n, err
}

func (m *Memory) takeFail(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.fail == nil {
		return nil
	}
	if m.failIn > 0 {
		m.failIn--
		return nil
	}
	err := m.fail
	m.fail = nil
	return err
}

func clone(r Record) Record {
	r.Steps = slices.Clone(r.Steps)
	r.Plan = slices.Clone(r.Plan)
	return r
}
