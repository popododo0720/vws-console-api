package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// launchIdle is how long a launch may sit running or undoing with no record
// write before the sweep undoes it. A request writes its record on every new
// step: its longest gap is about 70 seconds (two 30-second calls and a
// write), or about 2 minutes 10 seconds for an undo. A retry that replays
// recorded steps writes nothing until a new one, so a slow replay can be
// swept; it then fails Unavailable and leaves nothing.
const launchIdle = 10 * time.Minute

// launchSweepEvery is how often SweepLaunches looks for abandoned launches.
const launchSweepEvery = time.Minute

// sweepParallel bounds the undos one sweep runs at once. One process holds
// at most 100 launches, its in-flight cap, so the sweep after it dies at
// that cap ends in 5 rounds of at most undoTimeout each.
const sweepParallel = 20

// SweepLaunches undoes abandoned launches at once and then every
// launchSweepEvery until ctx ends. A failed sweep is reported, and the next
// one tries again. Without a tracker it returns at once.
func (c *Client) SweepLaunches(ctx context.Context) {
	if c.shared.launches == nil {
		return
	}
	tick := time.NewTicker(launchSweepEvery)
	defer tick.Stop()
	for {
		undone, err := computeClient{c.shared}.sweepLaunches(ctx)
		if undone > 0 {
			c.shared.logger().InfoContext(ctx, "abandoned launches undone", slog.Int("launches", undone))
		}
		if err != nil {
			_ = report.Error(ctx, fmt.Errorf("launch sweep: %w", err)) //nolint:errcheck // reported; the next sweep retries
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// sweepLaunches undoes every launch left running or undoing for launchIdle,
// as its latest attempt, sweepParallel at a time, and returns how many it
// marked failed. An undo it cut short stays undoing for the next sweep.
func (c computeClient) sweepLaunches(ctx context.Context) (int, error) {
	abandoned, err := c.launches.Abandoned(ctx, launchIdle)
	return forEachLaunch(ctx, abandoned, err, func(run *launch.Launch) (bool, error) {
		rec := run.Record()
		if err := c.undoLaunch(ctx, run, rec.Key); err != nil {
			return false, fmt.Errorf("undo launch %s attempt %d: %s", rec.Key, rec.Attempt, resource.CodeOf(err))
		}
		return run.Record().Phase == launch.Failed, nil
	})
}

// forEachLaunch runs each on every launch, sweepParallel at a time, and
// returns how many reported true, with listErr and every error each
// returned. Once ctx ends it starts no further launch. Each error names the
// launch key and the error code only, because a backend error names the
// account's resources.
func forEachLaunch(
	ctx context.Context, launches []launch.Launch, listErr error, each func(*launch.Launch) (bool, error),
) (int, error) {
	errs := []error{listErr}
	done := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, sweepParallel)
	for i := range launches {
		select {
		case <-ctx.Done():
		case slots <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		run := &launches[i]
		wg.Go(func() {
			defer func() { <-slots }()
			ok, err := each(run)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				done++
			}
		})
	}
	wg.Wait()
	return done, errors.Join(errs...)
}
