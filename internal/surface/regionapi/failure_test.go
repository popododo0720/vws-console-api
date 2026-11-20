package regionapi

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
)

func TestCanceledAndRepeatedReads(t *testing.T) {
	c, _ := loopback(t, config(fake.New(fake.Options{}).Set()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Version(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	for range 2 {
		if _, err := c.Version(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, origin := range []string{"http://region", "https://region/path", "https://user@region", "https://region?q=1"} {
		if _, err := NewClient(origin, nil); err == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
}
