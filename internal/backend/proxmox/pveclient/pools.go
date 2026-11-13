package pveclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var poolSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Pool reports whether the pool exists. GET /pools/{poolid} cannot name a
// nested pool, so parent/child pools (at most three levels) use GET /pools?poolid=.
func (c *Client) Pool(ctx context.Context, poolID string) (bool, error) {
	segments := strings.Split(poolID, "/")
	if len(segments) > 3 || !allMatch(segments, poolSegment) {
		return false, errors.New("pveclient: invalid pool id")
	}
	if len(segments) > 1 {
		return c.nestedPool(ctx, poolID)
	}
	pool, err := get[*struct{}](ctx, c, "/pools/"+poolID, nil)
	if he, ok := errors.AsType[*HTTPError](err); ok && he.poolNotFound() {
		return false, nil
	}
	if err == nil && pool == nil {
		return false, errors.New("pveclient: missing pool response")
	}
	return err == nil, err
}

func (c *Client) nestedPool(ctx context.Context, poolID string) (bool, error) {
	type poolRow struct {
		PoolID string `json:"poolid"`
	}
	pools, err := get[[]poolRow](ctx, c, "/pools", url.Values{"poolid": {poolID}})
	if he, ok := errors.AsType[*HTTPError](err); ok && he.poolNotFound() {
		return false, nil
	}
	if err == nil && pools == nil {
		return false, errors.New("pveclient: missing pool response")
	}
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(pools, func(p poolRow) bool { return p.PoolID == poolID }), nil
}

func allMatch(values []string, re *regexp.Regexp) bool {
	for _, v := range values {
		if !re.MatchString(v) {
			return false
		}
	}
	return true
}

func (e *HTTPError) poolNotFound() bool {
	return (e.Path == "/pools" || strings.HasPrefix(e.Path, "/pools/")) &&
		(e.Status == http.StatusNotFound ||
			e.Status == http.StatusInternalServerError && strings.Contains(e.Message, "does not exist"))
}
