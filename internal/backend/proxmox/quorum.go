package proxmox

import (
	"context"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	quorumFresh    = 5 * time.Second // A mutation needs a quorum check no older than this.
	quorumInterval = 2 * time.Second // The 2 s check timeout leaves room before the window ends.
)

// QuorumGate admits mutations only while a recent /cluster/status check
// reported quorum. One region daemon serves one cluster, so in-process locks
// already serialize writers; the gate only stops writes into a minority.
type QuorumGate struct {
	backend *Backend
	now     func() time.Time

	mu      sync.RWMutex
	quorate bool
	checked time.Time
	apiNode string
}

// NewQuorumGate returns a gate that is closed until the first check succeeds.
func NewQuorumGate(b *Backend) *QuorumGate {
	return &QuorumGate{backend: b, now: time.Now}
}

// Run refreshes the quorum check until ctx ends.
func (g *QuorumGate) Run(ctx context.Context) {
	ticker := time.NewTicker(quorumInterval)
	defer ticker.Stop()
	for {
		g.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *QuorumGate) check(ctx context.Context) {
	at := g.now()
	status, err := g.backend.clusterStatus(ctx)
	if ctx.Err() != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.quorate, g.checked = err == nil && status.Quorate, at
	if err == nil {
		g.apiNode = status.APINode
	}
}

// Admit refuses unless the last quorum check found quorum within quorumFresh.
func (g *QuorumGate) Admit(ctx context.Context) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if ctx.Err() != nil || !g.quorate || g.now().Sub(g.checked) > quorumFresh {
		return &resource.Error{Code: resource.CodeUnavailable, Message: "region has no quorum"}
	}
	return nil
}

// APINode returns the PVE node the last successful check connected to.
func (g *QuorumGate) APINode() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.apiNode
}
