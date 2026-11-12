package pveclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// TaskRow is an entry in the node task list.
type TaskRow struct {
	UPID      string `json:"upid"`
	Node      string `json:"node"`
	PID       uint32 `json:"pid"`
	StartTime uint32 `json:"starttime"`
	EndTime   int64  `json:"endtime"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	User      string `json:"user"`
	TokenID   string `json:"tokenid"`
	Status    string `json:"status"`
}

// OwnTasks lists only this token's tasks, including active tasks.
func (c *Client) OwnTasks(ctx context.Context, node string, q url.Values) ([]TaskRow, error) {
	n, err := segment("node", node)
	if err != nil {
		return nil, err
	}
	token, _, _ := strings.Cut(strings.TrimPrefix(string(c.auth), "PVEAPIToken="), "=")
	user, _, _ := strings.Cut(token, "!")
	q.Set("userfilter", user)
	q.Set("source", "all")
	rows, err := get[[]TaskRow](ctx, c, "/nodes"+n+"/tasks", q)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(rows, func(row TaskRow) bool { return row.User+"!"+row.TokenID != token }), nil
}

// ReadTask reads a task's completion status.
func (c *Client) ReadTask(ctx context.Context, task Task) (TaskStatus, error) {
	n, err := segment("node", task.Node)
	if err != nil {
		return TaskStatus{}, err
	}
	u, err := segment("upid", task.UPID)
	if err != nil {
		return TaskStatus{}, err
	}
	return get[TaskStatus](ctx, c, "/nodes"+n+"/tasks"+u+"/status", nil)
}

// Power submits a power action or a protected VM destroy.
func (c *Client) Power(ctx context.Context, vm VM, action string, timeout int) (string, error) {
	n, err := segment("node", vm.Node)
	if err != nil {
		return "", err
	}
	if vm.VMID < 100 || vm.VMID > 999999999 {
		return "", errors.New("pve power: invalid VM ID")
	}
	method, suffix, form := http.MethodPost, "/status/"+action, url.Values{}
	switch action {
	case "start", "stop", "reboot":
	case "shutdown":
		if timeout < 1 {
			return "", errors.New("pve power: invalid shutdown timeout")
		}
		form.Set("timeout", strconv.Itoa(timeout))
		form.Set("forceStop", "1")
	case "destroy":
		method, suffix = http.MethodDelete, ""
		form.Set("purge", "1")
		form.Set("destroy-unreferenced-disks", "1")
	default:
		return "", errors.New("pve power: unknown action")
	}
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json/nodes" + n + "/qemu/" + strconv.Itoa(vm.VMID) + suffix
	body := form.Encode()
	if method == http.MethodDelete {
		u.RawQuery, body = body, ""
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("pve power request: %w", err)
	}
	req.Header.Set("Authorization", string(c.auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pve power submit: %w", err)
	}
	var answer struct {
		Data string `json:"data"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&answer)
	err = errors.Join(err, resp.Body.Close())
	if resp.StatusCode/100 != 2 {
		return "", &HTTPError{Path: u.Path, Status: resp.StatusCode, Message: "power request refused"}
	}
	if err != nil {
		return "", fmt.Errorf("pve power answer: %w", err)
	}
	if answer.Data == "" {
		return "", errors.New("pve power: empty task ID")
	}
	return answer.Data, nil
}
