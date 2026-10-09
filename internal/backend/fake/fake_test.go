package fake

import (
	"bytes"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
)

func TestContract(t *testing.T) {
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x11}, 1<<16))
	now := time.Unix(1_700_000_000, 0).UTC()
	backendtest.Run(t, func() backend.Set {
		return New(Options{Now: func() time.Time { return now }, Entropy: entropy}).Set()
	})
}
