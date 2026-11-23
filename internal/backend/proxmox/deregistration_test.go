package proxmox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

func deregisterBody(generation int) []byte {
	return []byte(`{"region":"pve-test-1","generation":` + strconv.Itoa(generation) + `}`)
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestDeregisterRemovesTheStateFileAndIsIdempotent(t *testing.T) {
	conn, state := openForDeregistration(t)
	file := filepath.Join(state, registrationFile)
	temp := filepath.Join(state, "."+registrationFile+".tmp-crashed")
	writeFixture(t, file, []byte(`{"token":"fake-secret"}`))
	writeFixture(t, temp, []byte(`{"token":"fake-secret"}`))
	conn.current, conn.digest = &Backend{}, [32]byte{1}
	for i := range 2 {
		if removed, err := conn.Deregister(deregisterBody(5)); err != nil || !removed {
			t.Fatalf("deregistration %d: %v %v", i, removed, err)
		}
		if got := names(t, state); len(got) != 1 || got[0] != fenceFile {
			t.Fatalf("state directory after deregistration %d: %v", i, got)
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
		"other region":    `{"region":"pve-test-2","generation":3}`,
		"empty region":    `{"region":"","generation":3}`,
		"no generation":   `{"region":"pve-test-1"}`,
		"zero generation": `{"region":"pve-test-1","generation":0}`,
		"negative":        `{"region":"pve-test-1","generation":-1}`,
		"unknown field":   `{"region":"pve-test-1","generation":3,"force":true}`,
		"two documents":   `{"region":"pve-test-1","generation":3}{}`,
		"not an object":   `null`,
		"not JSON":        `pve-test-1`,
	} {
		removed, err := conn.Deregister([]byte(body))
		if e := resource.AsError(err); err == nil || removed || e.Code != resource.CodeInvalidArgument {
			t.Fatalf("%s: %v %v", name, removed, err)
		}
		if data, err := os.ReadFile(file); err != nil || string(data) != "kept" {
			t.Fatalf("%s changed the state file: %q %v", name, data, err)
		}
	}
	if got := names(t, state); len(got) != 1 {
		t.Fatalf("a refused request wrote state: %v", got)
	}
}

// A delayed or replayed message older than the removal is refused, whichever
// kind it is, and the removal itself can be repeated.
func TestStaleGenerationsAreRefusedAfterARemoval(t *testing.T) {
	conn, state := openForDeregistration(t)
	if removed, err := conn.Deregister(deregisterBody(9)); err != nil || !removed {
		t.Fatal(removed, err)
	}
	register := func(generation int) error {
		return conn.Register(t.Context(), []byte(`{"region":"pve-test-1","cluster_name":"test","generation":`+
			strconv.Itoa(generation)+`,"pveApiUrls":["https://pve1:8006"],"caPem":`+strconv.Quote(anyCA())+
			`,"tokenId":"vws@pve!inventory","token":"fake-secret"}`))
	}
	for _, generation := range []int{0, 8, 9} {
		if e := resource.AsError(register(generation)); e.Code != resource.CodeConflict {
			t.Fatalf("registration at generation %d after removal at 9: %v", generation, e)
		}
	}
	if removed, err := conn.Deregister(deregisterBody(8)); removed || resource.AsError(err).Code != resource.CodeConflict {
		t.Fatalf("an older removal was accepted: %v %v", removed, err)
	}
	if removed, err := conn.Deregister(deregisterBody(9)); !removed || err != nil {
		t.Fatalf("repeat of the removal: %v %v", removed, err)
	}
	if removed, err := conn.Deregister(deregisterBody(12)); !removed || err != nil {
		t.Fatalf("newer removal: %v %v", removed, err)
	}
	if got := names(t, state); len(got) != 1 || got[0] != fenceFile {
		t.Fatalf("state directory: %v", got)
	}
	if _, err := os.Stat(filepath.Join(state, registrationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// Cleanup of stale files comes first: if it fails nothing has changed and
// the caller must keep serving. After the unlink a failed sync is a committed
// teardown that a repeat completes.
func TestDeregisterFailurePoints(t *testing.T) {
	boom := errors.New("injected")
	for _, stage := range []string{"cleanup", "fence", "unlink"} {
		t.Run(stage, func(t *testing.T) {
			conn, state := openForDeregistration(t)
			file := filepath.Join(state, registrationFile)
			writeFixture(t, file, []byte("kept"))
			conn.current = &Backend{}
			conn.step = func(s string) error {
				if s == stage {
					return boom
				}
				return nil
			}
			if removed, err := conn.Deregister(deregisterBody(4)); !errors.Is(err, boom) || removed {
				t.Fatalf("%v %v", removed, err)
			}
			if data, err := os.ReadFile(file); err != nil || string(data) != "kept" || conn.current == nil {
				t.Fatalf("a failure before the unlink changed state: %q %v", data, err)
			}
			if _, err := os.Stat(filepath.Join(state, fenceFile)); stage != "unlink" && err == nil {
				t.Fatal("the generation was persisted before cleanup finished")
			}
			conn.step = nil
			if removed, err := conn.Deregister(deregisterBody(4)); err != nil || !removed {
				t.Fatalf("retry: %v %v", removed, err)
			}
		})
	}
	t.Run("sync", func(t *testing.T) {
		conn, state := openForDeregistration(t)
		writeFixture(t, filepath.Join(state, registrationFile), []byte("kept"))
		conn.current = &Backend{}
		conn.step = func(s string) error {
			if s == "sync" {
				return boom
			}
			return nil
		}
		removed, err := conn.Deregister(deregisterBody(4))
		if !errors.Is(err, boom) || !removed {
			t.Fatalf("a failed sync must report the committed removal: %v %v", removed, err)
		}
		if _, err := os.Stat(filepath.Join(state, registrationFile)); !errors.Is(err, os.ErrNotExist) || conn.current != nil {
			t.Fatalf("file or cached backend survived: %v", err)
		}
		syncs := 0
		conn.step = func(s string) error {
			if s == "sync" {
				syncs++
			}
			return nil
		}
		if removed, err := conn.Deregister(deregisterBody(4)); err != nil || !removed || syncs != 1 {
			t.Fatalf("retry: %v %v syncs=%d", removed, err, syncs)
		}
	})
}
