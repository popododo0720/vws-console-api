package storetest

import (
	"bytes"
	"errors"
	"testing"
	"testing/cryptotest"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func rgwCredentials(t *testing.T, b store.Backend) {
	cryptotest.SetGlobalRandom(t, 796)
	ctx := t.Context()
	k, err := secret.New("rgw-kek", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	project, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	g := store.New(b)
	r, err := store.SealRGWKey(k, project, "access-canary-796", "secret-canary-796")
	if err != nil {
		t.Fatal(err)
	}
	r, err = g.RGWKeys().Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Get(ctx, "rgw-keys/"+project.String())
	if err != nil || bytes.Contains(raw.Value, []byte("canary")) {
		t.Fatalf("plaintext persisted: %v", err)
	}
	access, value, err := store.New(b).OpenRGWKey(ctx, k, project)
	if err != nil || access != "access-canary-796" || value != "secret-canary-796" {
		t.Fatal("credentials lost across registry recreation")
	}
	old := r
	r, err = g.RGWKeys().Update(ctx, r)
	if err != nil || r.Version == old.Version {
		t.Fatal("credential version did not advance")
	}
	if _, err := g.RGWKeys().Update(ctx, old); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	version := r.Version
	r.Project = "210987654321"
	if _, err := g.RGWKeys().Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID](r.Project)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.OpenRGWKey(ctx, k, other); err == nil {
		t.Fatal("ciphertext transplanted to another project")
	}
	if err := g.RGWKeys().Delete(ctx, project.String(), old.Version); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := g.RGWKeys().Delete(ctx, project.String(), version); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.OpenRGWKey(ctx, k, project); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing credential: %v", err)
	}
}
