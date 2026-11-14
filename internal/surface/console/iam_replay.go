package console

import (
	"context"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type iamReplayKey struct {
	account   resource.AccountID
	principal string
	token     string
}

type iamReplay struct {
	result      any
	err         error
	expires     time.Time
	fingerprint [32]byte
	done        chan struct{}
}

type iamCreate struct {
	key         iamReplayKey
	fingerprint [32]byte
	now         time.Time
}

type iamReplays struct {
	mu      sync.Mutex
	records map[iamReplayKey]*iamReplay
}

func (s *iamReplays) create(ctx context.Context, in iamCreate, run func() (any, error)) (any, error) {
	s.mu.Lock()
	if rec, ok := s.records[in.key]; ok && (rec.expires.IsZero() || in.now.Before(rec.expires)) {
		s.mu.Unlock()
		if rec.fingerprint != in.fingerprint {
			return nil, resource.IdempotencyMismatch()
		}
		select {
		case <-rec.done:
			return rec.result, rec.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rec := &iamReplay{fingerprint: in.fingerprint, done: make(chan struct{})}
	if s.records == nil {
		s.records = make(map[iamReplayKey]*iamReplay)
	}
	s.records[in.key] = rec
	s.mu.Unlock()
	result, err := run()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.result, rec.err = result, err
	if err != nil {
		delete(s.records, in.key)
	} else {
		rec.expires = in.now.Add(24 * time.Hour)
		if len(s.records) > 4096 {
			key, expiry := in.key, rec.expires
			for k, candidate := range s.records {
				// In-flight records cannot be evicted: their waiters share
				// the pending backend call.
				if !candidate.expires.IsZero() && candidate.expires.Before(expiry) {
					key, expiry = k, candidate.expires
				}
			}
			delete(s.records, key)
		}
	}
	close(rec.done)
	return result, err
}
