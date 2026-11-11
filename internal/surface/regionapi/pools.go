package regionapi

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type poolResult struct {
	Exists bool `json:"exists"`
}

func checkPool(pool string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(pool) {
		return resource.Invalid("pool", "expected a pool id of 1 to 64 characters")
	}
	return nil
}

// PoolExists checks the live pool inventory over the region's mTLS connection.
func (c *Client) PoolExists(ctx context.Context, pool string) (bool, error) {
	if err := checkPool(pool); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var result poolResult
	err := c.do(ctx, http.MethodGet, "/internal/v1/pools/"+pool, nil, &result)
	return result.Exists, err
}
