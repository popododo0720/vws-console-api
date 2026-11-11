package console

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAdminHealthFailureMessagesAreSafe(t *testing.T) {
	e, _ := adminFixture(t)
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("credential-canary"), "region status unavailable"},
		{fmt.Errorf("wrapped credential-canary: %w", context.DeadlineExceeded), "context deadline exceeded"},
		{fmt.Errorf("wrapped credential-canary: %w", dial), dial.Error()},
	} {
		e.h.(*handler).regionStatus = func(context.Context, string) (resource.RegionStatus, error) {
			return resource.RegionStatus{}, tc.err
		}
		rec := e.do(t, "GET", "/api/v1/admin/regions/pve-lab-1/health", "",
			map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), tc.want) ||
			strings.Contains(rec.Body.String(), "credential-canary") {
			t.Fatalf("unsafe or missing health failure: %d %s", rec.Code, rec.Body)
		}
	}
}
