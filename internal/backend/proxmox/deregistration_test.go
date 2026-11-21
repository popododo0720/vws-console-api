package proxmox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func openForDeregistration(t *testing.T) (*Connection, string) {
	t.Helper()
	dir := privateDir(t)
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "state")
	conn, err := Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	return conn, state
}

func TestDeregisterRemovesTheStateFileAndIsIdempotent(t *testing.T) {
	conn, state := openForDeregistration(t)
	file := filepath.Join(state, registrationFile)
	temp := filepath.Join(state, "."+registrationFile+".tmp-crashed")
	writeFixture(t, file, []byte(`{"token":"fake-secret"}`))
	writeFixture(t, temp, []byte(`{"token":"fake-secret"}`))
	conn.current, conn.digest = &Backend{}, [32]byte{1}
	for i := range 2 {
		if err := conn.Deregister([]byte(`{"region":"pve-test-1"}`)); err != nil {
			t.Fatalf("deregistration %d: %v", i, err)
		}
		entries, err := os.ReadDir(state)
		if err != nil || len(entries) != 0 {
			t.Fatalf("state directory after deregistration %d: %v %v", i, entries, err)
		}
		if _, err := conn.Check(t.Context()); err == nil || err.Error() != "unregistered" {
			t.Fatalf("readiness reason = %v, want unregistered", err)
		}
		if conn.current != nil {
			t.Fatal("the cached backend outlived the registration")
		}
	}
}

func TestDeregisterChecksTheRequest(t *testing.T) {
	conn, state := openForDeregistration(t)
	file := filepath.Join(state, registrationFile)
	writeFixture(t, file, []byte("kept"))
	for name, body := range map[string]string{
		"other region":  `{"region":"pve-test-2"}`,
		"empty region":  `{"region":""}`,
		"empty object":  `{}`,
		"unknown field": `{"region":"pve-test-1","force":true}`,
		"two documents": `{"region":"pve-test-1"}{}`,
		"not an object": `null`,
		"not JSON":      `pve-test-1`,
	} {
		err := conn.Deregister([]byte(body))
		if e := resource.AsError(err); err == nil || e.Code != resource.CodeInvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
		if data, err := os.ReadFile(file); err != nil || string(data) != "kept" {
			t.Fatalf("%s changed the state file: %q %v", name, data, err)
		}
	}
}

// A failed removal reports the error and keeps the cached backend; a retry
// after the cause is gone succeeds.
func TestDeregisterFailureKeepsStateAndCanBeRepeated(t *testing.T) {
	conn, state := openForDeregistration(t)
	// A non-empty directory in place of the file makes os.Remove fail.
	blocker := filepath.Join(state, registrationFile)
	if err := os.MkdirAll(filepath.Join(blocker, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	conn.current = &Backend{}
	if err := conn.Deregister([]byte(`{"region":"pve-test-1"}`)); err == nil {
		t.Fatal("a failed removal reported success")
	}
	if conn.current == nil {
		t.Fatal("a failed removal dropped the cached backend")
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	if err := conn.Deregister([]byte(`{"region":"pve-test-1"}`)); err != nil || conn.current != nil {
		t.Fatalf("retry: %v", err)
	}
}
