package pveclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// VolumeWrite sends one write without retrying an ambiguous submission.
// Callers recover from PVE inventory before submitting again.
func (c *Client) VolumeWrite(ctx context.Context, method, path string, form url.Values, out any) (err error) {
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json" + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("pve volume write: request: %w", err)
	}
	req.Header.Set("Authorization", string(c.auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pve volume write %s: %w", path, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	body := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode/100 != 2 {
		env := struct {
			Message string `json:"message"`
		}{Message: resp.Status}
		if decodeErr := json.NewDecoder(body).Decode(&env); decodeErr != nil {
			return fmt.Errorf("pve volume write %s: status %d: %w", path, resp.StatusCode, decodeErr)
		}
		return &HTTPError{Path: path, Status: resp.StatusCode, Message: env.Message}
	}
	env := struct {
		Data any `json:"data"`
	}{Data: out}
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		return fmt.Errorf("pve volume write %s: decode: %w", path, err)
	}
	return nil
}

// NextVolumeVMID reads the allocator without reserving an ID.
func (c *Client) NextVolumeVMID(ctx context.Context) (int, error) {
	var id json.Number
	id, err := get[json.Number](ctx, c, "/cluster/nextid", nil)
	if err != nil {
		return 0, err
	}
	n, err := id.Int64()
	if err != nil || n < 100 || n > 999999999 {
		return 0, fmt.Errorf("pve volume holder: invalid next VM ID %q", id)
	}
	return int(n), nil
}
