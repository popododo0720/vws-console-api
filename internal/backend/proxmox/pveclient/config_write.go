package pveclient

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WriteConfigTags synchronously replaces tags and description using config CAS.
// The caller rereads and recomputes the update after a digest conflict.
func (c *Client) WriteConfigTags(
	ctx context.Context, vm VM, digest, tags, description string,
) (err error) {
	path, err := vm.path()
	if err != nil {
		return err
	}
	if digest == "" {
		return errors.New("pve config: digest required")
	}
	path += "/config"
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json" + path
	form := url.Values{"digest": {digest}, "tags": {tags}, "description": {description}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("pve PUT %s: %w", path, err)
	}
	req.Header.Set("Authorization", string(c.auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pve PUT %s: %w", path, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("pve PUT %s: close body: %w", path, closeErr)
		}
	}()
	var answer struct {
		Message string `json:"message"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&answer)
	if resp.StatusCode/100 != 2 {
		return &HTTPError{
			Path: path, Status: resp.StatusCode,
			Message: cmp.Or(answer.Message, strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)+" ")),
		}
	}
	if decodeErr != nil {
		return fmt.Errorf("pve PUT %s: decode: %w", path, decodeErr)
	}
	return nil
}

// DigestConflict distinguishes stale config from other PVE failures.
func DigestConflict(err error) bool {
	he, ok := errors.AsType[*HTTPError](err)
	return ok && he.Status == http.StatusInternalServerError &&
		strings.Contains(he.Message, "checksum mismatch")
}
