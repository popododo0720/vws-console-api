package pveclient

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Pool reports whether GET /pools/{poolid} finds the pool.
func (c *Client) Pool(ctx context.Context, poolID string) (bool, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(poolID) {
		return false, errors.New("pveclient: invalid pool id")
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

func (e *HTTPError) poolNotFound() bool {
	return strings.HasPrefix(e.Path, "/pools/") &&
		(e.Status == http.StatusNotFound ||
			e.Status == http.StatusInternalServerError && strings.Contains(e.Message, "does not exist"))
}
