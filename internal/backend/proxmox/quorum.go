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

// quorumProbe is the one deadline all probes of a check share.
const quorumProbe = 2 * time.Second

func errNoQuorum() error {
	return &resource.Error{Code: resource.CodeUnavailable, Message: "region has no quorum"}
}

type probeResult struct {
	status resource.RegionStatus
	err    error
}

func (r probeResult) quorate() bool { return r.err == nil && r.status.Quorate }

// check probes /cluster/status on every registered address at once (at most
// 16), each pinned to its address and bounded by its own attempt limits, all
// under one shared deadline, so stalled addresses cost one deadline in total
// and never hide a healthy one. Each address's result is recorded: quorate
// ones are marked so writes may go to them, the others lose their mark. The
// current address stays when it is quorate; otherwise the first quorate
// address in list order becomes current. When none is quorate the index does
// not move. The recorded time is the start of the check.
func (g *QuorumGate) check(ctx context.Context) {
	endpoints := g.backend.endpoints
	if endpoints == nil {
		at := g.now()
		status, err := g.backend.clusterStatus(ctx)
		if ctx.Err() == nil {
			g.record(at, probeResult{status, err})
		}
		return
	}
	at, marked := g.now(), time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, quorumProbe)
	defer cancel()
	results := make([]probeResult, endpoints.Len())
	var wg sync.WaitGroup
	for idx := range results {
		wg.Go(func() {
			status, err := g.backend.clusterStatus(pveclient.WithEndpoint(probeCtx, idx))
			results[idx] = probeResult{status, err}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	chosen := endpoints.Index()
	if !results[chosen].quorate() {
		for idx, r := range results {
			if r.quorate() {
				chosen = idx
				break
			}
		}
	}
	for idx, r := range results {
		if r.quorate() {
			endpoints.MarkQuorate(idx, marked)
		} else {
			endpoints.ClearQuorum(idx)
		}
	}
	if results[chosen].quorate() {
		endpoints.Use(chosen)
	}
	g.record(at, results[chosen])
}

func (g *QuorumGate) record(at time.Time, r probeResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return
	}
	g.quorate, g.checked = r.quorate(), at
	if r.err == nil {
		g.apiNode = r.status.APINode
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
