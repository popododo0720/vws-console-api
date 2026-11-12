package pveclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ActiveSnapshotTask finds this token's snapshot task while the VM is locked.
func (c *Client) ActiveSnapshotTask(ctx context.Context, vm VM) (string, error) {
	node, err := segment("node", vm.Node)
	if err != nil {
		return "", err
	}
	token, _, _ := strings.Cut(strings.TrimPrefix(string(c.auth), "PVEAPIToken="), "=")
	user, _, _ := strings.Cut(token, "!")
	rows, err := get[[]struct {
		UPID string `json:"upid"`
	}](ctx, c, "/nodes"+node+"/tasks", url.Values{
		"vmid": {strconv.Itoa(vm.VMID)}, "typefilter": {"qmsnapshot"}, "userfilter": {user},
		"source": {"active"},
	})
	if err != nil {
		return "", fmt.Errorf("pve snapshot replay task: %w", err)
	}
	for _, row := range rows {
		if strings.HasSuffix(row.UPID, ":"+token+":") {
			return row.UPID, nil
		}
	}
	return "", nil
}

// CreateSnapshot submits a disk-only snapshot of the complete VM.
func (c *Client) CreateSnapshot(ctx context.Context, vm VM, name, description string) (string, error) {
	path, err := vm.path()
	if err != nil {
		return "", err
	}
	if _, err := segment("snapshot", name); err != nil {
		return "", err
	}
	path += "/snapshot"
	form := url.Values{
		"snapname": {name}, "description": {description}, "vmstate": {"0"},
	}
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("pve snapshot request: %w", err)
	}
	req.Header.Set("Authorization", string(c.auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// A lost write response may already have submitted a task. Replay checks the
	// snapshot marker instead of blindly repeating a non-idempotent POST.
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pve snapshot write: %w", err)
	}
	var answer struct {
		Data    string `json:"data"`
		Message string `json:"message"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&answer)
	err = errors.Join(err, resp.Body.Close())
	if resp.StatusCode/100 != 2 {
		return "", &HTTPError{Path: path, Status: resp.StatusCode, Message: c.Redact(answer.Message)}
	}
	if err != nil {
		return "", fmt.Errorf("pve snapshot response: %w", err)
	}
	if answer.Data == "" {
		return "", fmt.Errorf("pve snapshot response: missing task")
	}
	return answer.Data, nil
}
