package pveclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// Clone allocates the recovery description atomically with the new VM.
// The source is a template; its UPID must never identify the destination.
func (c *Client) Clone(
	ctx context.Context, source VM, newid int, pool, name, description, target string, full bool,
) (string, error) {
	path, err := source.path()
	if err != nil {
		return "", err
	}
	if newid < 100 || newid > 999999999 || pool == "" || description == "" {
		return "", errors.New("pve clone: destination, pool and recovery description required")
	}
	form := url.Values{
		"newid": {strconv.Itoa(newid)}, "pool": {pool}, "name": {name},
		"description": {description}, "full": {"0"},
	}
	if full {
		form.Set("full", "1")
	}
	if target != "" {
		form.Set("target", target)
	}
	var upid string
	err = c.VolumeWrite(ctx, http.MethodPost, path+"/clone", form, &upid)
	if err == nil && upid == "" {
		err = errors.New("pve clone: empty task ID")
	}
	return upid, err
}
