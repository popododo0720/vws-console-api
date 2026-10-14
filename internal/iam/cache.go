package iam

import (
	"context"
	"sync"
	"time"
)

// NewCache keeps successful key lookups for ttl, so a burst of requests with
// one key costs one IAM call. Unknown keys and errors are not cached, and
// Authorize always goes through: a policy change applies on the next request.
func NewCache(next Client, ttl time.Duration, now func() time.Time) Client {
	if now == nil {
		now = time.Now
	}
	return &cache{next: next, ttl: ttl, now: now, keys: map[string]cached{}}
}

type cached struct {
	cred SigningCredential
	at   time.Time
}

type cache struct {
	next Client
	ttl  time.Duration
	now  func() time.Time
	mu   sync.Mutex
	keys map[string]cached
}

func (c *cache) GetSigningCredential(ctx context.Context, accessKey string) (SigningCredential, error) {
	c.mu.Lock()
	e, ok := c.keys[accessKey]
	c.mu.Unlock()
	if ok && c.now().Sub(e.at) < c.ttl {
		return e.cred, nil
	}
	cred, err := c.next.GetSigningCredential(ctx, accessKey)
	if err != nil {
		return SigningCredential{}, err
	}
	c.mu.Lock()
	c.keys[accessKey] = cached{cred: cred, at: c.now()}
	c.mu.Unlock()
	return cred, nil
}

func (c *cache) Authorize(ctx context.Context, req Request) (Decision, error) {
	return c.next.Authorize(ctx, req)
}
