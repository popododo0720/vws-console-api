package pveclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Clone allocates the recovery description atomically with the new VM.
// The source is a template; its UPID must never identify the destination.
func (c *Client) Clone(
	ctx context.Context, source VM, newid int, pool, name, description, target string, full bool, storage ...string,
) (string, error) {
	path, err := source.path()
	if err != nil {
		return "", err
	}
	if len(storage) > 1 || target != "" && !validCloneName(target) {
		return "", errors.New("pve clone: invalid storage or target")
	}
	if len(storage) == 1 && (len(storage[0]) > 64 ||
		!regexp.MustCompile(`(?i)^[a-z][a-z0-9._-]*[a-z0-9]$`).MatchString(storage[0])) {
		return "", errors.New("pve clone: invalid storage")
	}
	if newid < 100 || newid > 999999999 || len(pool) > 64 ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(pool) ||
		!validCloneName(name) || description == "" || len(description) > 8192 ||
		!utf8.ValidString(description) || strings.ContainsRune(description, 0) {
		return "", errors.New("pve clone: invalid destination, pool, name or recovery description")
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
	if len(storage) == 1 {
		form.Set("storage", storage[0])
	}
	var upid string
	err = c.VolumeWrite(ctx, http.MethodPost, path+"/clone", form, &upid)
	if err == nil && upid == "" {
		err = errors.New("pve clone: empty task ID")
	}
	return upid, err
}

func validCloneName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 || !regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`).MatchString(label) {
			return false
		}
	}
	return true
}
