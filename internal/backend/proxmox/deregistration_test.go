package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
		if removed, err := conn.Deregister(t.Context(), deregisterBody(5)); err != nil || !removed {
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
		"other region":     `{"region":"pve-test-2","generation":3}`,
		"empty region":     `{"region":"","generation":3}`,
		"no generation":    `{"region":"pve-test-1"}`,
		"zero generation":  `{"region":"pve-test-1","generation":0}`,
		"negative":         `{"region":"pve-test-1","generation":-1}`,
		"unknown field":    `{"region":"pve-test-1","generation":3,"force":true}`,
		"two documents":    `{"region":"pve-test-1","generation":3}{}`,
		"not an object":    `null`,
		"not JSON":         `pve-test-1`,
		"region twice":     `{"region":"pve-test-2","region":"pve-test-1","generation":3}`,
		"generation twice": `{"region":"pve-test-1","generation":3,"generation":4}`,
	} {
		removed, err := conn.Deregister(t.Context(), []byte(body))
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

// A request whose caller gave up, for example while it waited for the
// lifecycle locks, removes nothing and writes no tombstone.
func TestDeregisterAfterTheCallerGaveUpChangesNothing(t *testing.T) {
	conn, state := openForDeregistration(t)
	file := filepath.Join(state, registrationFile)
	writeFixture(t, file, []byte("kept"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if removed, err := conn.Deregister(ctx, deregisterBody(5)); removed || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled deregistration: %v %v", removed, err)
	}
	if got := names(t, state); len(got) != 1 || got[0] != registrationFile {
		t.Fatalf("a canceled deregistration changed the state: %v", got)
	}
	if removed, err := conn.Deregister(t.Context(), deregisterBody(5)); !removed || err != nil {
		t.Fatalf("deregistration after the canceled one: %v %v", removed, err)
	}
}

// A delayed or replayed message older than the removal is refused, whichever
// kind it is, and the removal itself can be repeated.
func TestStaleGenerationsAreRefusedAfterARemoval(t *testing.T) {
	conn, state := openForDeregistration(t)
	if removed, err := conn.Deregister(t.Context(), deregisterBody(9)); err != nil || !removed {
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
	removed, err := conn.Deregister(t.Context(), deregisterBody(8))
	if removed || resource.AsError(err).Code != resource.CodeConflict {
		t.Fatalf("an older removal was accepted: %v %v", removed, err)
	}
	if removed, err := conn.Deregister(t.Context(), deregisterBody(9)); !removed || err != nil {
		t.Fatalf("repeat of the removal: %v %v", removed, err)
	}
	if removed, err := conn.Deregister(t.Context(), deregisterBody(12)); !removed || err != nil {
		t.Fatalf("newer removal: %v %v", removed, err)
	}
	if got := names(t, state); len(got) != 1 || got[0] != fenceFile {
		t.Fatalf("state directory: %v", got)
	}
	if _, err := os.Stat(filepath.Join(state, registrationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// Cleanup of stale files comes first: if it or the tombstone write fails
// nothing has changed and the caller must keep serving. Once the pending
// tombstone is persisted the removal is committed: a failed unlink or sync
// still reports the registration removed and gone from readiness, and a later
// reload or repeat finishes the cleanup.
func TestDeregisterFailurePoints(t *testing.T) {
	boom := errors.New("injected")
	failAt := func(conn *Connection, stage string) {
		conn.step = func(s string) error {
			if s == stage {
				return boom
			}
			return nil
		}
	}
	for _, stage := range []string{"cleanup", "fence"} {
		t.Run(stage, func(t *testing.T) {
			conn, state := openForDeregistration(t)
			file := filepath.Join(state, registrationFile)
			writeFixture(t, file, []byte("kept"))
			conn.current = &Backend{}
			failAt(conn, stage)
			if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); !errors.Is(err, boom) || removed {
				t.Fatalf("%v %v", removed, err)
			}
			if data, err := os.ReadFile(file); err != nil || string(data) != "kept" || conn.current == nil {
				t.Fatalf("a failure before the tombstone changed state: %q %v", data, err)
			}
			if _, err := os.Stat(filepath.Join(state, fenceFile)); err == nil {
				t.Fatal("the generation was persisted")
			}
			conn.step = nil
			if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); err != nil || !removed {
				t.Fatalf("retry: %v %v", removed, err)
			}
		})
	}
	t.Run("unlink", func(t *testing.T) {
		conn, state := openForDeregistration(t)
		file := filepath.Join(state, registrationFile)
		writeFixture(t, file, []byte("kept"))
		conn.current = &Backend{}
		failAt(conn, "unlink")
		if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); !errors.Is(err, boom) || !removed {
			t.Fatalf("a failed unlink after the tombstone must report the removal: %v %v", removed, err)
		}
		if conn.current != nil {
			t.Fatal("the cached backend outlived the removal")
		}
		// An operator repairs the permissions of the old file: chmod and chown
		// change its ctime, not its identity, so it is still the removed file.
		changeMetadata(t, file)
		// Readiness reports the registration gone while the unlink keeps failing,
		// so the daemon stops the old quorum gate and finalizer.
		if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) || !errors.Is(err, boom) {
			t.Fatalf("readiness while the cleanup fails: %v", err)
		}
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("the injected failure did not keep the file: %v", err)
		}
		conn.step = nil
		if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) || errors.Is(err, boom) {
			t.Fatalf("a later pass did not finish the cleanup: %v", err)
		}
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the file survived the later pass: %v", err)
		}
		if f, err := conn.readFence(); err != nil || f != (fence{Generation: 4, Deregistered: true}) {
			t.Fatalf("tombstone after the later pass: %+v %v", f, err)
		}
		if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); err != nil || !removed {
			t.Fatalf("retry: %v %v", removed, err)
		}
	})
	t.Run("sync", func(t *testing.T) {
		conn, state := openForDeregistration(t)
		writeFixture(t, filepath.Join(state, registrationFile), []byte("kept"))
		conn.current = &Backend{}
		failAt(conn, "sync")
		removed, err := conn.Deregister(t.Context(), deregisterBody(4))
		if !errors.Is(err, boom) || !removed {
			t.Fatalf("a failed sync must report the committed removal: %v %v", removed, err)
		}
		if _, err := os.Stat(filepath.Join(state, registrationFile)); !errors.Is(err, os.ErrNotExist) || conn.current != nil {
			t.Fatalf("file or cached backend survived: %v", err)
		}
		// A retry whose recovery fails after the unlink still reports the removal.
		if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); !errors.Is(err, boom) || !removed {
			t.Fatalf("retry with the sync still failing: %v %v", removed, err)
		}
		syncs := 0
		conn.step = func(s string) error {
			if s == "sync" {
				syncs++
			}
			return nil
		}
		if removed, err := conn.Deregister(t.Context(), deregisterBody(4)); err != nil || !removed || syncs == 0 {
			t.Fatalf("retry: %v %v syncs=%d", removed, err, syncs)
		}
	})
}

// A crash after the tombstone commits and before the unlink leaves the old
// credentials on disk beside a pending tombstone that names their digest and
// inode.
// They must not come back, on startup or on a reload, and the pending unlink
// is finished. Other bytes beside it were written since and are kept.
func TestTombstoneBesideARegistrationFileIsAuthoritative(t *testing.T) {
	state := filepath.Join(privateDir(t), "state")
	config := filepath.Join(filepath.Dir(state), "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	old, err := encodeState(registrationSnapshot{
		Region: "pve-test-1", ClusterName: "test", PVEAPIURLs: []string{"https://pve1:8006"}, CAPEM: anyCA(),
		TokenID: "vws@pve!inventory", Token: "fake-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(state, registrationFile)
	var pending fence
	leave := func() {
		t.Helper()
		writeFixture(t, file, old)
		digest, id, err := conn.stateFile()
		if err != nil || id == (fileID{}) {
			t.Fatalf("identity: %+v %v", id, err)
		}
		pending = fence{Generation: 9, Deregistered: true, Pending: true, RemovedDigest: digest, RemovedFile: id}
		if err := conn.writeFence(pending); err != nil {
			t.Fatal(err)
		}
	}
	leave()
	conn.Close()
	for _, phase := range []string{"startup", "reload"} {
		if phase == "startup" {
			if conn, err = Open(config, "pve-test-1", state); err != nil {
				t.Fatal(err)
			}
		} else {
			leave()
		}
		if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) {
			t.Fatalf("%s: the removed registration is ready: %v", phase, err)
		}
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the pending unlink was not finished: %v", phase, err)
		}
		if f, err := conn.readFence(); err != nil || f != (fence{Generation: 9, Deregistered: true}) {
			t.Fatalf("%s: tombstone not marked done: %+v %v", phase, f, err)
		}
	}
	// A tombstone written where statx reported no birth time still owns the
	// unchanged file once a later lookup reports one.
	leave()
	pending.RemovedFile.Btime = 0
	if err := conn.writeFence(pending); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("without a recorded birth time the removed registration is ready: %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("without a recorded birth time the pending unlink was not finished: %v", err)
	}
	// A rolled-back daemon re-registered other credentials after the crash.
	if err := conn.writeFence(pending); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, file, append(old, ' '))
	if _, err := conn.Check(t.Context()); errors.Is(err, ErrUnregistered) {
		t.Fatalf("a newer registration was taken for the leftover: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("a newer registration was erased: %v", err)
	}
	if f, err := conn.readFence(); err != nil || f != (fence{Generation: 9}) {
		t.Fatalf("the fence after a newer registration: %+v %v", f, err)
	}
}

func fencedRegistration(t *testing.T, pve *httptest.Server, generation int) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": []string{pve.URL}, "caPem": serverCA(pve),
		"tokenId": "vws@pve!inventory", "token": "fake-secret", "generation": generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A registration that supplies every secret skips the stored-registration
// read, so it must finish a pending removal itself before it replaces the
// tombstone: a failure after that cannot serve the removed registration.
func TestRegistrationWithEverySecretFinishesAPendingRemoval(t *testing.T) {
	pve, _ := clusterFake(t, "test")
	conn, state := openFixture(t)
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected")
	fail := func(stage string) {
		conn.step = func(s string) error {
			if s == stage {
				return boom
			}
			return nil
		}
	}
	fail("unlink")
	if removed, err := conn.Deregister(t.Context(), deregisterBody(5)); !removed || !errors.Is(err, boom) {
		t.Fatalf("deregistration: %v %v", removed, err)
	}
	fail("persist")
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 6)); !errors.Is(err, boom) {
		t.Fatalf("registration: %v", err)
	}
	conn.step = nil
	if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("the removed registration is served: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, registrationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the removed registration is on disk: %v", err)
	}
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Check(t.Context()); err != nil {
		t.Fatalf("the new registration is not ready: %v", err)
	}
}

// Delete, roll the daemon back, re-register through the older binary, which
// knows no fence, and upgrade again: the registration made after the removal
// is kept and served, and the removal's generation stays fenced.
func TestRegistrationByARolledBackDaemonSurvivesTheReUpgrade(t *testing.T) {
	pve, _ := clusterFake(t, "test")
	dir := privateDir(t)
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "state")
	conn, err := Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 3)); err != nil {
		t.Fatal(err)
	}
	if removed, err := conn.Deregister(t.Context(), deregisterBody(5)); err != nil || !removed {
		t.Fatalf("deregistration: %v %v", removed, err)
	}
	if _, err := conn.Check(t.Context()); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("after deregistration: %v", err)
	}
	conn.Close()
	// The older binary writes its own schema, by temporary file and rename,
	// and leaves generation.json alone.
	legacy, err := json.Marshal(struct {
		Region      string   `json:"region"`
		ClusterName string   `json:"cluster_name"` //nolint:tagliatelle // the registration protocol
		PVEAPIURLs  []string `json:"pveApiUrls"`
		CAPEM       string   `json:"caPem"`
		Zones       []any    `json:"zones"`
		TokenID     string   `json:"tokenId"`
		Token       string   `json:"token,omitempty"`
	}{"pve-test-1", "test", []string{pve.URL}, serverCA(pve), nil, "vws@pve!inventory", "fake-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(state, registrationFile, legacy, nil); err != nil {
		t.Fatal(err)
	}
	conn, err = Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if _, err := conn.Check(t.Context()); err != nil {
		t.Fatalf("the upgraded daemon dropped the newer registration: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(state, registrationFile)); err != nil || !bytes.Equal(data, legacy) {
		t.Fatalf("the newer registration changed on disk: %v", err)
	}
	for _, generation := range []int{0, 4} {
		err := conn.Register(t.Context(), fencedRegistration(t, pve, generation))
		if e := resource.AsError(err); err == nil || e.Code != resource.CodeConflict {
			t.Fatalf("registration at generation %d after removal at 5: %v", generation, err)
		}
	}
	for _, generation := range []int{4, 5} {
		if removed, err := conn.Deregister(t.Context(), deregisterBody(generation)); removed ||
			resource.AsError(err).Code != resource.CodeConflict {
			t.Fatalf("a removal at %d reached the newer registration: %v %v", generation, removed, err)
		}
	}
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Check(t.Context()); err != nil {
		t.Fatalf("after a newer registration: %v", err)
	}
}

// registration.json keeps the schema of earlier releases: a daemon rolled back
// still reads it, because the generation lives only in generation.json.
func TestStateFileKeepsTheLegacySchema(t *testing.T) {
	state, err := encodeState(registrationSnapshot{
		Region: "pve-test-1", ClusterName: "test", PVEAPIURLs: []string{"https://pve1:8006"}, CAPEM: anyCA(),
		TokenID: "vws@pve!inventory", Token: "fake-secret", Generation: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	type legacy struct {
		Region      string   `json:"region"`
		ClusterName string   `json:"cluster_name"` //nolint:tagliatelle // the registration protocol
		PVEAPIURLs  []string `json:"pveApiUrls"`
		CAPEM       string   `json:"caPem"`
		Zones       []any    `json:"zones"`
		TokenID     string   `json:"tokenId"`
		Token       string   `json:"token,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(state))
	dec.DisallowUnknownFields()
	var old legacy
	if err := dec.Decode(&old); err != nil {
		t.Fatalf("the previous schema refuses the state file: %v\n%s", err, state)
	}
}

// A crash in the middle of a removal leaves the old file beside a pending
// tombstone. A daemon rolled back to the older binary serves it, and a
// re-registration with the same credentials writes the same bytes by
// temporary file and rename. That is a new inode: the upgraded daemon keeps
// it and is ready, while the untouched leftover is still removed.
func TestByteIdenticalRegistrationAfterARollbackIsKept(t *testing.T) {
	pve, _ := clusterFake(t, "test")
	dir := privateDir(t)
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "state")
	file := filepath.Join(state, registrationFile)
	conn, err := Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Register(t.Context(), fencedRegistration(t, pve, 3)); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash")
	conn.step = func(s string) error {
		if s == "unlink" {
			return crash
		}
		return nil
	}
	if removed, err := conn.Deregister(t.Context(), deregisterBody(5)); !removed || !errors.Is(err, crash) {
		t.Fatalf("deregistration: %v %v", removed, err)
	}
	conn.Close()
	old, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(state, registrationFile, old, nil); err != nil {
		t.Fatal(err)
	}
	conn, err = Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if _, err := conn.Check(t.Context()); err != nil {
		t.Fatalf("the upgraded daemon dropped the re-registration: %v", err)
	}
	if data, err := os.ReadFile(file); err != nil || !bytes.Equal(data, old) {
		t.Fatalf("the re-registration changed on disk: %v", err)
	}
	if f, err := conn.readFence(); err != nil || f != (fence{Generation: 5}) {
		t.Fatalf("the fence after the re-registration: %+v %v", f, err)
	}
}

// changeMetadata runs chmod and chown on file without touching its bytes, and
// waits until its ctime has moved, so the change is visible at the kernel's
// timestamp granularity.
func changeMetadata(t *testing.T, file string) {
	t.Helper()
	ctime := func() int64 {
		var st unix.Stat_t
		if err := unix.Lstat(file, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ctim.Nano()
	}
	before := ctime()
	for deadline := time.Now().Add(time.Second); ctime() == before; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("ctime did not change")
		}
		if err := os.Chmod(file, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(file, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileIdentityComparesBirthTimesOnlyWhenBothHaveOne(t *testing.T) {
	removed := fileID{Dev: 1, Ino: 7, Btime: 100}
	for name, tc := range map[string]struct {
		a, b fileID
		same bool
	}{
		"equal":                   {removed, removed, true},
		"recorded, then not seen": {removed, fileID{Dev: 1, Ino: 7}, true},
		"not recorded, then seen": {fileID{Dev: 1, Ino: 7}, removed, true},
		"different birth time":    {removed, fileID{Dev: 1, Ino: 7, Btime: 200}, false},
		"different inode":         {removed, fileID{Dev: 1, Ino: 8, Btime: 100}, false},
		"different device":        {removed, fileID{Dev: 2, Ino: 7, Btime: 100}, false},
		"unknown identity":        {fileID{}, fileID{}, false},
	} {
		if got := tc.b.sameFile(tc.a); got != tc.same {
			t.Errorf("%s: sameFile = %v, want %v", name, got, tc.same)
		}
	}
}
