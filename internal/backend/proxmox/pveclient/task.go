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
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
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
		wait := time.NewTimer(jitter(c.poll))
		select {
		case <-ctx.Done():
			wait.Stop()
			return fmt.Errorf("wait for task %s: %w", t.UPID, ctx.Err())
		case <-wait.C:
		}
	}
}
