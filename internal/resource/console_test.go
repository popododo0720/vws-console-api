package resource

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestConsoleSessionURLIsNeverEncoded keeps the backend's internal address
// out of any JSON a surface writes.
func TestConsoleSessionURLIsNeverEncoded(t *testing.T) {
	got, err := json.Marshal(ConsoleSession{Kind: ConsoleVNC, URL: "wss://internal.invalid/x", Expires: time.Unix(0, 0)})
	if err != nil || strings.Contains(string(got), "internal.invalid") {
		t.Fatalf("%s %v", got, err)
	}
}
