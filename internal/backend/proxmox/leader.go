package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const leaderPath = "/etc/pve/vws/leader"

// LeaseWriter confines privileged lease writes and mkdir locks to the helper.
type LeaseWriter interface {
	Lock(context.Context, string) error
	WriteLease(context.Context, []byte) error
	Unlock(context.Context, string) error
}

type leaderLease struct {
	Node string `json:"node"`
	Term uint64 `json:"term"`
	//nolint:tagliatelle // The pmxcfs lease protocol uses lease_until.
	Until time.Time `json:"lease_until"`
}

// Leader fences mutation decisions with a pmxcfs lease and live quorum.
type Leader struct {
	backend *Backend
	node    string
	helper  LeaseWriter
	read    func(string) ([]byte, error)
	path    string
	now     func() time.Time
	ticks   func(time.Duration) (<-chan time.Time, func())

	mu        sync.RWMutex
	lease     leaderLease
	ownedTerm uint64
	quorate   bool
	checked   time.Time
	announced string
}

// NewLeader discovers the local PVE node; Run starts its election loop.
func NewLeader(ctx context.Context, b *Backend, helper LeaseWriter, path string) (*Leader, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := b.client.ClusterStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("leader local node: %w", err)
	}
	for _, row := range rows {
		if row.Type == "node" && row.Local == 1 && registrationCluster.MatchString(row.Name) {
			return &Leader{
				backend: b, node: row.Name, helper: helper, path: path, read: os.ReadFile, now: time.Now,
				ticks: func(d time.Duration) (<-chan time.Time, func()) {
					t := time.NewTicker(d)
					return t.C, t.Stop
				},
			}, nil
		}
	}
	return nil, errors.New("leader local node unavailable")
}

func (l *Leader) readLease() (leaderLease, error) {
	data, err := l.read(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return leaderLease{}, nil
	}
	if err != nil {
		return leaderLease{}, fmt.Errorf("read leader lease: %w", err)
	}
	var lease leaderLease
	if len(data) > 4096 || json.Unmarshal(data, &lease) != nil ||
		!registrationCluster.MatchString(lease.Node) || lease.Term == 0 || lease.Until.IsZero() {
		return leaderLease{}, errors.New("invalid leader lease")
	}
	return lease, nil
}

// Run renews every five seconds and refreshes quorum every two seconds.
func (l *Leader) Run(ctx context.Context) {
	quorumTicks, stopQuorum := l.ticks(2 * time.Second)
	leaseTicks, stopLease := l.ticks(5 * time.Second)
	defer stopQuorum()
	defer stopLease()
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.quorate, l.ownedTerm = false, 0
		l.announce(ctx)
	}()
	l.checkQuorum(ctx)
	if err := l.renew(ctx); err != nil && ctx.Err() == nil {
		slog.Default().WarnContext(ctx, "leader lease unavailable", slog.String("reason", err.Error()))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-quorumTicks:
			l.checkQuorum(ctx)
		case <-leaseTicks:
			if err := l.renew(ctx); err != nil && ctx.Err() == nil {
				slog.Default().WarnContext(ctx, "leader lease unavailable", slog.String("reason", err.Error()))
			}
		}
	}
}

func (l *Leader) checkQuorum(ctx context.Context) {
	at := l.now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	status, err := l.backend.Status(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quorate, l.checked = err == nil && status.Quorate, at
	if !l.quorate {
		l.ownedTerm = 0
	}
	l.announce(ctx)
}

func (l *Leader) renew(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	lease, err := l.readLease()
	if err != nil {
		l.lease, l.ownedTerm = leaderLease{}, 0
		l.announce(ctx)
		return err
	}
	l.lease = lease
	defer l.announce(ctx)
	if !l.hasQuorum() {
		return nil
	}
	if err := l.helper.Lock(ctx, "leader"); err != nil {
		return fmt.Errorf("lock leader lease: %w", err)
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer unlockCancel()
		err = errors.Join(err, l.helper.Unlock(unlockCtx, "leader"))
	}()
	lease, err = l.readLease()
	if err != nil {
		l.lease, l.ownedTerm = leaderLease{}, 0
		return err
	}
	l.lease = lease
	now := l.now()
	own := lease.Node == l.node && lease.Term == l.ownedTerm && now.Before(lease.Until)
	if !own && !now.After(lease.Until) {
		return nil
	}
	if !l.hasQuorum() {
		return nil
	}
	if !own {
		if lease.Term == math.MaxUint64 {
			return errors.New("leader term exhausted")
		}
		lease.Term++
	}
	lease.Node, lease.Until = l.node, now.Add(20*time.Second)
	data, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("encode leader lease: %w", err)
	}
	if err := l.helper.WriteLease(ctx, data); err != nil {
		return fmt.Errorf("write leader lease: %w", err)
	}
	l.lease, l.ownedTerm = lease, lease.Term
	return nil
}

func (l *Leader) hasQuorum() bool {
	return l.quorate && l.now().Sub(l.checked) <= 2*time.Second
}

func (l *Leader) current() string {
	if !l.now().Before(l.lease.Until) || (l.lease.Node == l.node &&
		(!l.hasQuorum() || l.ownedTerm != l.lease.Term)) {
		return ""
	}
	return l.lease.Node
}

func (l *Leader) announce(ctx context.Context) {
	node := l.current()
	if node != l.announced {
		slog.Default().InfoContext(ctx, "region leader changed",
			slog.String("node", node), slog.Uint64("term", l.lease.Term))
		l.announced = node
	}
}

// Current returns the unexpired leader for the operations gauge.
func (l *Leader) Current() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current()
}

// Quorate reports whether the last quorum check is still fresh.
func (l *Leader) Quorate() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.hasQuorum()
}

// Admit returns an empty node for a fenced local leader, or a peer to forward to.
func (l *Leader) Admit(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", &resource.Error{Code: resource.CodeUnavailable, Message: "region leader unavailable"}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	node := l.current()
	if node == "" || (node == l.node && l.lease.Until.Sub(l.now()) <= 5*time.Second) {
		return "", &resource.Error{Code: resource.CodeUnavailable, Message: "region leader unavailable"}
	}
	if node == l.node {
		return "", nil
	}
	return node, nil
}
