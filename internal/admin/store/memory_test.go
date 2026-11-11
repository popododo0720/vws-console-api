package store_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/storetest"
)

func TestMemoryHonorsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Backend { return store.NewMemory() })
}
