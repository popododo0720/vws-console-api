package proxmox

import (
	"context"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	quorumFresh    = pveclient.QuorumFresh // A mutation needs a quorum check no older than this.
	quorumInterval = 2 * time.Second       // The 2 s check timeout leaves room before the window ends.
)

// QuorumGate admits mutations only while a recent /cluster/status check
// reported quorum. One region daemon serves one cluster, so in-process locks
// already serialize writers; the gate only stops writes into a minority.
type QuorumGate struct {
	backend *Backend
	now     func() time.Time

	mu      sync.RWMutex
	stopped bool
	quorate bool
	checked time.Time
	apiNode string
}

// NewQuorumGate returns a gate that is closed until the first check succeeds.
func NewQuorumGate(b *Backend) *QuorumGate {
	return &QuorumGate{backend: b, now: time.Now}
}

// Run refreshes the quorum check until ctx ends. When it returns the gate is
// closed for good, so a handler that outlives the poller is refused.
func (g *QuorumGate) Run(ctx context.Context) {
	defer g.stop()
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

func (g *QuorumGate) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped, g.quorate = true, false
}

// quorumWalk stops a check from starting a probe of another address after
// this long.
const quorumWalk = pveclient.FailoverBudget

func errNoQuorum() error {
	return &resource.Error{Code: resource.CodeUnavailable, Message: "region has no quorum"}
}

// check probes /cluster/status address by address, starting at the current
// one, each probe pinned to its address under its own 2 s timeout. The first
// address that reports quorum becomes the current one and is marked as
// quorate, so writes may go to it; addresses that fail or report no quorum
// lose their mark. A minority node is thus left within one check. The
// recorded time is the start of the last probe, so a long walk never extends
// the freshness of a reading.
func (g *QuorumGate) check(ctx context.Context) {
	endpoints := g.backend.endpoints
	probes, start := 1, 0
	if endpoints != nil {
		probes, start = endpoints.Len(), endpoints.Index()
	}
	var (
		at     time.Time
		status resource.RegionStatus
		err    error
	)
	began := time.Now()
	for k := range probes {
		if k > 0 && time.Since(began) > quorumWalk {
			break
		}
		probe, idx := ctx, (start+k)%probes
		marked := time.Now()
		if endpoints != nil {
			probe = pveclient.WithEndpoint(ctx, idx)
		}
		at = g.now()
		status, err = g.backend.clusterStatus(probe)
		if ctx.Err() != nil {
			return
		}
		if endpoints == nil {
			break
		}
		if err == nil && status.Quorate {
			endpoints.MarkQuorate(idx, marked)
			endpoints.Use(idx)
			break
		}
		endpoints.ClearQuorum(idx)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return
	}
	g.quorate, g.checked = err == nil && status.Quorate, at
	if err == nil {
		g.apiNode = status.APINode
	}
}

// Admit refuses unless the last quorum check found quorum within quorumFresh
// and the address requests now go to is the one that reported it.
func (g *QuorumGate) Admit(ctx context.Context) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if ctx.Err() != nil || !g.quorate || g.now().Sub(g.checked) > quorumFresh {
		return errNoQuorum()
	}
	if endpoints := g.backend.endpoints; endpoints != nil && !endpoints.Quorate(endpoints.Index()) {
		return errNoQuorum()
	}
	return nil
}

// APINode returns the PVE node the last successful check connected to.
func (g *QuorumGate) APINode() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.apiNode
}
