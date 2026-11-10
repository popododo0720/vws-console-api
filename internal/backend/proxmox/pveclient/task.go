package pveclient

import (
	"context"
	"fmt"
	"time"
)

// Task wait limits per action (design.md 3.3.6).
const (
	CloneWait = 10 * time.Minute
	StartWait = 2 * time.Minute
	StopWait  = 5 * time.Minute
)

// exitStatusOK is the exitstatus of a task that succeeded. The PVE apidoc only
// calls exitstatus an optional string; this literal is unconfirmed until the
// live check pins it (design.md 3.3.6 and 4.8, marked [U]).
const exitStatusOK = "OK"

// Task names one PVE task: the node that runs it and its UPID.
type Task struct {
	Node string
	UPID string
}

// TaskStatus is GET /nodes/{node}/tasks/{upid}/status.
type TaskStatus struct {
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
	Type       string `json:"type"`
	ID         string `json:"id"`
	StartTime  int64  `json:"starttime"`
}

// clock is the time source of WaitTask. Tests replace it so that a wait to
// the limit costs no real time.
type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// TaskError is a task that stopped with an exitstatus other than OK.
type TaskError struct {
	UPID       string
	ExitStatus string
}

func (e *TaskError) Error() string {
	return fmt.Sprintf("pve task %s failed: %s", e.UPID, e.ExitStatus)
}

// WaitTask polls the task status about once per poll interval, with jitter,
// until it is stopped or limit passes. A stopped task with exitstatus OK is
// nil; any other exitstatus is a *TaskError.
func (c *Client) WaitTask(ctx context.Context, t Task, limit time.Duration) error {
	n, err := segment("node", t.Node)
	if err != nil {
		return err
	}
	u, err := segment("upid", t.UPID)
	if err != nil {
		return err
	}
	// The context deadline bounds a status read still in flight at the limit;
	// between reads the clock decides when the limit has passed.
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	deadline := c.clock.Now().Add(limit)
	path := "/nodes" + n + "/tasks" + u + "/status"
	for {
		st, err := get[TaskStatus](ctx, c, path, nil)
		if err != nil {
			return fmt.Errorf("wait for task %s: %w", t.UPID, err)
		}
		if st.Status == "stopped" {
			if st.ExitStatus == exitStatusOK {
				return nil
			}
			return &TaskError{UPID: t.UPID, ExitStatus: st.ExitStatus}
		}
		wait := min(jitter(c.poll), deadline.Sub(c.clock.Now()))
		if wait <= 0 {
			return fmt.Errorf("wait for task %s: %w", t.UPID, context.DeadlineExceeded)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for task %s: %w", t.UPID, ctx.Err())
		case <-c.clock.After(wait):
		}
	}
}
