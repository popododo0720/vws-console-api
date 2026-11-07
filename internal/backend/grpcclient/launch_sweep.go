package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
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

// SweepLaunches undoes abandoned launches and then collects dead launch
// attempts, at once and then every launchSweepEvery until ctx ends. A failed sweep is reported, and the next
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
		collected, err := computeClient{c.shared}.collectLaunches(ctx)
		if collected > 0 {
			c.shared.logger().InfoContext(ctx, "dead launch attempts collected", slog.Int("launches", collected))
		}
		if err != nil {
			_ = report.Error(ctx, fmt.Errorf("launch gc: %w", err)) //nolint:errcheck // reported; the next pass retries
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

// collectLaunches deletes what dead attempts left: every planned volume and
// instance of each attempt a failed or succeeded launch can no longer use,
// for launches idle launchIdle, sweepParallel at a time. A create can land
// after its attempt was undone, by a request that a retry replaced or that
// the backend applied late; the undo of that attempt never sees it. The ids
// are derived from the key and the attempt, so each attempt's plan names
// them all, and a delete of a missing resource succeeds. The succeeded
// attempt and every running or undoing launch are never touched. It returns
// how many launches it marked collected. A launch it cut short is collected
// again by the next pass; each failure names the launch key and the error
// code only.
func (c computeClient) collectLaunches(ctx context.Context) (int, error) {
	dead, err := c.launches.Collectable(ctx, launchIdle)
	return forEachLaunch(ctx, dead, err, func(run *launch.Launch) (bool, error) {
		rec := run.Record()
		if err := c.collectAttempts(ctx, run); err != nil {
			return false, fmt.Errorf("collect launch %s: %s", rec.Key, resource.CodeOf(err))
		}
		return true, nil
	})
}

// collectAttempts deletes the plan of each dead attempt not yet collected,
// last step first, and records each attempt collected once its plan is
// gone, so a launch with many attempts makes progress across passes. One
// launch takes at most undoTimeout per pass.
func (c computeClient) collectAttempts(ctx context.Context, run *launch.Launch) error {
	ctx, cancel := context.WithTimeout(ctx, undoTimeout)
	defer cancel()
	rec := run.Record()
	projectID := project(rec.Account)
	for attempt := rec.Collected + 1; attempt <= rec.Dead(); attempt++ {
		for _, step := range slices.Backward(launchPlan(projectID, rec.Key, attempt, rec.Count)) {
			if err := c.undoStep(ctx, "gc-", rec.Key, attempt, step); err != nil {
				return err
			}
		}
		if err := run.Collected(ctx, attempt); err != nil {
			return err
		}
	}
	return nil
}
