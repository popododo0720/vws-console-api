package proxmox

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	pbsTokenID = "dr@pbs!export"
	pbsSecret  = "pbs-read-secret-6f2c"
	drPath     = "/datastore/dr-store/vws/pve-test-1"
)

// pbsEntry is one ACL entry of a token. Nil privileges is the NoAccess role.
type pbsEntry struct {
	path       string
	privileges []string
	propagate  bool
}

// pbsFake is a PBS at the boundary. It answers GET
// /api2/json/access/permissions for the tokens it knows from their ACL
// entries as PBS's AclTree::roles does: along the path, the entries of the
// deepest node that has any replace the inherited ones; above the last node
// only propagating entries count, and a NoAccess entry holds nothing. Without
// path it lists each ACL node where the token holds something; with path it
// answers that path. The owner's privileges are not modeled.
type pbsFake struct {
	mu      sync.Mutex
	tokens  map[string][]pbsEntry // "id:secret" -> entries
	calls   int
	longest int // the longest path asked for
}

func newPBSFake(t *testing.T) (*pbsFake, *httptest.Server) {
	t.Helper()
	f := &pbsFake{tokens: map[string][]pbsEntry{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *pbsFake) grant(id, secret string, entries ...pbsEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[id+":"+secret] = entries
}

// reader is the stock DatastoreReader role on path, propagated as the PBS UI does by default.
func reader(path string) pbsEntry { return pbsEntry{path: path, privileges: drReader, propagate: true} }

// hidden is Chip's counterexample at path: a non-propagating NoAccess hides
// the node, while privileges propagate to every child of it.
func hidden(path string, privileges ...string) []pbsEntry {
	return []pbsEntry{{path: path}, {path: path, privileges: privileges, propagate: true}}
}

func effective(entries []pbsEntry, path string) map[string]bool {
	nodes := []string{"/"}
	if path != "/" {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i := range parts {
			nodes = append(nodes, "/"+strings.Join(parts[:i+1], "/"))
		}
	}
	held := map[string]bool{}
	for i, node := range nodes {
		last := i == len(nodes)-1
		found, none := false, false
		roles := map[string]bool{}
		for _, e := range entries {
			if e.path != node || !last && !e.propagate {
				continue
			}
			found = true
			if e.privileges == nil {
				none = true
			}
			for _, p := range e.privileges {
				roles[p] = true
			}
		}
		if found {
			held = roles
			if none {
				held = map[string]bool{}
			}
		}
	}
	return held
}

func (f *pbsFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	credential, ok := strings.CutPrefix(r.Header.Get("Authorization"), "PBSAPIToken=")
	entries, known := f.tokens[credential]
	if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/permissions" || !ok || !known {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	data := map[string]map[string]bool{}
	if path := r.URL.Query().Get("path"); path != "" {
		f.longest = max(f.longest, len(path))
		if len(path) > pbsMaxPath {
			http.Error(w, "path: value too long", http.StatusBadRequest)
			return
		}
		if held := effective(entries, path); len(held) > 0 {
			data[path] = held
		}
	} else {
		for _, e := range entries {
			if held := effective(entries, e.path); len(held) > 0 {
				data[e.path] = held
			}
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// errField is the field of a resource error, and "" for none.
func errField(err error) string {
	if e := resource.AsError(err); e != nil {
		return e.Field
	}
	return ""
}

func pbsServerFingerprint(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return pbsFingerprintOf(sum[:])
}

func pbsTargetFor(srv *httptest.Server, id, secret string) *pbsTarget {
	return &pbsTarget{
		address: strings.TrimPrefix(srv.URL, "https://"), datastore: "dr-store", namespace: "vws/pve-test-1",
		fingerprint: pbsServerFingerprint(srv), tokenID: id, token: secret,
	}
}

// drReader is the stock PBS DatastoreReader role.
var drReader = []string{"Datastore.Audit", "Datastore.Verify", "Datastore.Read"}

func TestPBSTokenScope(t *testing.T) {
	admin := []string{"Datastore.Audit", "Datastore.Read", "Datastore.Modify", "Datastore.Backup"}
	many := []pbsEntry{reader(drPath)}
	for i := range pbsMaxListed {
		many = append(many, reader(fmt.Sprintf("%s/n%d", drPath, i)))
	}
	for _, tc := range []struct {
		name    string
		entries []pbsEntry
		want    string
	}{
		{name: "DatastoreReader on the namespace", entries: []pbsEntry{reader(drPath)}},
		{name: "read only", entries: []pbsEntry{{path: drPath, privileges: []string{"Datastore.Read"}, propagate: true}}},
		{name: "not propagated", entries: []pbsEntry{{path: drPath, privileges: drReader}}},
		{name: "reader on a child namespace too", entries: []pbsEntry{reader(drPath), reader(drPath + "/old")}},
		{
			name:    "backup privilege",
			entries: []pbsEntry{{path: drPath, privileges: append([]string{"Datastore.Backup"}, drReader...), propagate: true}},
			want:    "Datastore.Backup on " + drPath,
		},
		{
			name:    "modify privilege",
			entries: []pbsEntry{{path: drPath, privileges: append([]string{"Datastore.Modify"}, drReader...), propagate: true}},
			want:    "Datastore.Modify",
		},
		{
			name: "reader on the whole datastore", entries: []pbsEntry{reader("/datastore/dr-store"), reader(drPath)},
			want: "on /datastore/dr-store",
		},
		{
			name: "reader on another namespace", entries: []pbsEntry{reader(drPath), reader("/datastore/dr-store/other")},
			want: "on /datastore/dr-store/other",
		},
		{
			name: "a sibling with the same prefix", entries: []pbsEntry{reader(drPath), reader(drPath + "x")},
			want: "on " + drPath + "x",
		},
		{
			name:    "system audit",
			entries: []pbsEntry{reader(drPath), {path: "/", privileges: []string{"Sys.Audit"}}},
			want:    "Sys.Audit on /",
		},
		{
			name:    "a hidden grant on the datastore",
			entries: append(hidden("/datastore/dr-store", admin...), reader(drPath)),
			want:    "on /datastore/dr-store/vws",
		},
		{
			name:    "a hidden grant on the parent namespace",
			entries: append(hidden("/datastore/dr-store/vws", admin...), reader(drPath)),
			want:    "on /datastore/dr-store/vws/vp",
		},
		{
			name: "a hidden grant at the root", entries: append(hidden("/", admin...), reader(drPath)),
			want: "on /datastore",
		},
		{
			name:    "a hidden grant on /access",
			entries: append(hidden("/access", "Sys.Audit"), reader(drPath)),
			want:    "Sys.Audit on /access/vp",
		},
		{name: "too many listed paths", entries: many, want: "lists 65 ACL paths"},
		{
			name:    "audit only",
			entries: []pbsEntry{{path: drPath, privileges: []string{"Datastore.Audit"}, propagate: true}},
			want:    "lacks Datastore.Read on " + drPath,
		},
		{name: "no grant", want: "lacks Datastore.Read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newPBSFake(t)
			f.grant(pbsTokenID, pbsSecret, tc.entries...)
			err := checkPBS(t.Context(), pbsTargetFor(srv, pbsTokenID, pbsSecret))
			var sc *selfCheckError
			switch {
			case tc.want == "":
				checkLaunch(t, err)
			case !errors.As(err, &sc) || sc.check != "pbs_privileges" || !strings.Contains(err.Error(), tc.want):
				t.Fatalf("checkPBS = %v, want pbs_privileges naming %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), pbsSecret) {
				t.Fatalf("the diagnostic carries the token: %v", err)
			}
		})
	}
}

// PBS refuses an ACL path over 128 characters, so a probe that long is
// never sent and the token is refused.
func TestPBSProbePathsFitTheACLPathLimit(t *testing.T) {
	f, srv := newPBSFake(t)
	p := pbsTargetFor(srv, pbsTokenID, pbsSecret)
	level := strings.Repeat("n", 31)
	p.namespace = strings.Join([]string{level, level, level, level}, "/")
	f.grant(pbsTokenID, pbsSecret, reader("/datastore/dr-store/"+p.namespace))
	err := checkPBS(t.Context(), p)
	var sc *selfCheckError
	if !errors.As(err, &sc) || sc.check != "pbs_privileges" || !strings.Contains(err.Error(), "exceeds 128") {
		t.Fatalf("checkPBS = %v", err)
	}
	if f.longest > pbsMaxPath {
		t.Fatalf("a %d-character path was sent", f.longest)
	}
}

func TestPBSConnectionChecks(t *testing.T) {
	f, srv := newPBSFake(t)
	f.grant(pbsTokenID, pbsSecret, reader(drPath))
	for name, change := range map[string]func(*pbsTarget){
		"another certificate": func(p *pbsTarget) { p.fingerprint = strings.Repeat("00:", 31) + "00" },
		"a wrong secret":      func(p *pbsTarget) { p.token = "other-secret" },
	} {
		t.Run(name, func(t *testing.T) {
			p := pbsTargetFor(srv, pbsTokenID, pbsSecret)
			change(p)
			err := checkPBS(t.Context(), p)
			var sc *selfCheckError
			if !errors.As(err, &sc) || sc.check != "pbs_connection" {
				t.Fatalf("checkPBS = %v, want pbs_connection", err)
			}
			if strings.Contains(err.Error(), pbsSecret) || strings.Contains(err.Error(), "other-secret") {
				t.Fatalf("the diagnostic carries the token: %v", err)
			}
		})
	}
}

// drScenario adds the PBS storage dr-pbs, a second one dr-pbs2, to scenario.
func drScenario() pvefake.Scenario {
	s := scenario()
	s.Storages = append(s.Storages, pvefake.Storage{Node: "pve1", Name: "dr-pbs", Type: "pbs"},
		pvefake.Storage{Node: "pve1", Name: "dr-pbs2", Type: "pbs"})
	return s
}

// drRegion is a daemon against pvefake and a PBS fake that knows the
// read-only token, and register pushes a registration with DR settings.
type drRegion struct {
	t                *testing.T
	pve              *httptest.Server
	pbs              *pbsFake
	pbsSrv           *httptest.Server
	config, state    string
	conn             *Connection
	repository, fing string
}

func newDRRegion(t *testing.T) *drRegion {
	t.Helper()
	dir := privateDir(t)
	f, err := pvefake.New(drScenario())
	checkLaunch(t, err)
	pve := httptest.NewTLSServer(f)
	t.Cleanup(pve.Close)
	pbs, pbsSrv := newPBSFake(t)
	pbs.grant(pbsTokenID, pbsSecret, reader(drPath))
	r := &drRegion{
		t: t, pve: pve, pbs: pbs, pbsSrv: pbsSrv,
		config: filepath.Join(dir, "region.yaml"), state: filepath.Join(dir, "state"),
		repository: strings.TrimPrefix(pbsSrv.URL, "https://") + ":dr-store", fing: pbsServerFingerprint(pbsSrv),
	}
	writeFixture(t, r.config, []byte("read_only: true\n"))
	r.conn = r.open()
	return r
}

func (r *drRegion) open() *Connection {
	conn, err := Open(r.config, "pve-test-1", r.state)
	checkLaunch(r.t, err)
	return conn
}

// register pushes a registration with the DR settings and the read-only
// token; a field set to "" in fields is left out, and dr false leaves out
// every DR setting.
func (r *drRegion) register(dr bool, fields map[string]string) error {
	urls, ca := target(r.t, r.pve)
	input := map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
		"pveApiUrls": urls, "caPem": ca, "token": "fake-secret",
	}
	if dr {
		for k, v := range map[string]string{
			"drStorage": "dr-pbs", "pbsRepository": r.repository, "pbsNamespace": "vws/pve-test-1",
			"pbsFingerprint": r.fing, "pbsTokenId": pbsTokenID, "pbsToken": pbsSecret,
		} {
			input[k] = v
		}
	}
	for k, v := range fields {
		if v == "" {
			delete(input, k)
		} else {
			input[k] = v
		}
	}
	data, err := json.Marshal(input)
	checkLaunch(r.t, err)
	return r.conn.Register(r.t.Context(), data)
}

func (r *drRegion) coldDR(conn *Connection) string {
	r.t.Helper()
	b, err := conn.Check(r.t.Context())
	checkLaunch(r.t, err)
	caps, err := b.RegionCapabilities(r.t.Context(), "pve-test-1")
	checkLaunch(r.t, err)
	return caps.Features.ColdDR
}

// stored is the one DR record a completed registration leaves, without its binding.
func (r *drRegion) stored() drState {
	r.t.Helper()
	data, err := os.ReadFile(filepath.Join(r.state, drFile))
	checkLaunch(r.t, err)
	records, err := decodeDR(data)
	checkLaunch(r.t, err)
	if len(records) != 1 {
		r.t.Fatalf("dr.json holds %d records after a registration", len(records))
	}
	dr := records[0]
	dr.Registration = drBinding{}
	return dr
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: %v", filepath.Base(path), err)
	}
}

func TestPBSRegistration(t *testing.T) {
	r := newDRRegion(t)
	r.pbs.grant("dr@pbs!broad", "broad-secret",
		pbsEntry{path: drPath, privileges: append([]string{"Datastore.Backup"}, drReader...), propagate: true})

	// A token that can do more than read the DR namespace is refused, and nothing is stored.
	err := r.register(true, map[string]string{"pbsTokenId": "dr@pbs!broad", "pbsToken": "broad-secret"})
	if err == nil || resource.AsError(err).Message != "registration self-check failed: pbs_privileges" {
		t.Fatalf("over-privileged PBS token: %v", err)
	}
	if strings.Contains(err.Error(), "broad-secret") {
		t.Fatalf("the refusal carries the token: %v", err)
	}
	absent(t, filepath.Join(r.state, registrationFile))
	absent(t, filepath.Join(r.state, drFile))
	// A first registration has no stored secret to reuse.
	if err := r.register(true, map[string]string{"pbsToken": ""}); errField(err) != "pbsToken" {
		t.Fatalf("first PBS registration without secret: %v", err)
	}
	// The read-only token is accepted; a restart reports DR configured from the state files alone.
	checkLaunch(t, r.register(true, nil))
	if got := r.coldDR(r.open()); got != resource.ColdDRConfigured {
		t.Fatalf("coldDr after PBS registration: %q", got)
	}
	calls := r.pbs.calls
	r.pbsSrv.Close()
	if got := r.coldDR(r.open()); got != resource.ColdDRConfigured {
		t.Fatalf("a restart with PBS down: %q", got)
	}
	if r.pbs.calls != calls {
		t.Fatal("a reload contacted PBS")
	}
	if dr := r.stored(); dr != (drState{
		Storage: "dr-pbs", Repository: r.repository, Namespace: "vws/pve-test-1", Fingerprint: r.fing,
		TokenID: pbsTokenID, Token: pbsSecret,
	}) {
		t.Fatalf("dr.json: %+v", dr)
	}
	// A registration without DR settings removes them.
	checkLaunch(t, r.register(false, nil))
	absent(t, filepath.Join(r.state, drFile))
	if got := r.coldDR(r.open()); got != resource.ColdDRNotConfigured {
		t.Fatalf("coldDr after DR was removed: %q", got)
	}
}

// drStorage must name a PVE storage of type pbs; a refusal stores nothing.
func TestDRStorageMustBeAKnownPBSStorage(t *testing.T) {
	r := newDRRegion(t)
	for _, storage := range []string{"missing", "local"} {
		err := r.register(true, map[string]string{"drStorage": storage})
		if err == nil || resource.AsError(err).Message != "registration self-check failed: dr_storage" {
			t.Fatalf("drStorage %s: %v", storage, err)
		}
		absent(t, filepath.Join(r.state, registrationFile))
		absent(t, filepath.Join(r.state, drFile))
	}
	checkLaunch(t, r.register(true, nil))
}

func TestPBSSecretReuse(t *testing.T) {
	r := newDRRegion(t)
	other, otherSrv := newPBSFake(t)
	other.grant(pbsTokenID, pbsSecret, reader(drPath))
	checkLaunch(t, r.register(true, nil))
	// The same repository and fingerprint reuse the stored secret, which PBS checks again.
	calls := r.pbs.calls
	checkLaunch(t, r.register(true, map[string]string{"pbsToken": ""}))
	if r.pbs.calls == calls {
		t.Fatal("reuse did not check the stored token")
	}
	// A namespace or a storage is no destination: the token goes to the same PBS.
	r.pbs.grant(pbsTokenID, pbsSecret, reader("/datastore/dr-store/vws/other"))
	checkLaunch(t, r.register(true, map[string]string{"pbsToken": "", "pbsNamespace": "vws/other"}))
	checkLaunch(t, r.register(true, map[string]string{
		"pbsToken": "", "pbsNamespace": "vws/other", "drStorage": "dr-pbs2",
	}))
	if dr := r.stored(); dr.Token != pbsSecret || dr.Storage != "dr-pbs2" {
		t.Fatalf("dr.json after reuse: storage %s", dr.Storage)
	}
	for name, fields := range map[string]map[string]string{
		"another repository": {"pbsRepository": strings.TrimPrefix(otherSrv.URL, "https://") + ":dr-store"},
		"another datastore":  {"pbsRepository": strings.TrimPrefix(r.pbsSrv.URL, "https://") + ":dr-other"},
		// httptest servers share one certificate, so this fingerprint names no server.
		"another fingerprint": {"pbsFingerprint": strings.Repeat("ab:", 31) + "ab"},
		"another token":       {"pbsTokenId": "dr@pbs!other"},
	} {
		t.Run(name, func(t *testing.T) {
			fields["pbsToken"] = ""
			calls := r.pbs.calls + other.calls
			if err := r.register(true, fields); errField(err) != "pbsToken" {
				t.Fatalf("reuse for %s: %v", name, err)
			}
			if r.pbs.calls+other.calls != calls {
				t.Fatal("the stored secret was sent to a new destination")
			}
		})
	}
}

// A region without DR settings registers as before, writes no dr.json and
// reports cold DR as not configured.
func TestRegionWithoutPBSReportsColdDRNotConfigured(t *testing.T) {
	r := newDRRegion(t)
	checkLaunch(t, r.register(false, nil))
	stored, err := os.ReadFile(filepath.Join(r.state, registrationFile))
	checkLaunch(t, err)
	if bytes.Contains(stored, []byte("pbs")) || bytes.Contains(stored, []byte("drStorage")) {
		t.Fatalf("state of a region without DR: %s", stored)
	}
	absent(t, filepath.Join(r.state, drFile))
	if got := r.coldDR(r.conn); got != resource.ColdDRNotConfigured {
		t.Fatalf("coldDr %q", got)
	}
}

// preDRSnapshot is registrationSnapshot as releases before cold DR decode
// it, unknown fields refused: an older daemon must still read the
// registration.json this one writes.
type preDRSnapshot struct {
	Region          string         `json:"region"`
	ClusterName     string         `json:"cluster_name"` //nolint:tagliatelle // the registration protocol
	PVEAPIURLs      []string       `json:"pveApiUrls"`
	CAPEM           string         `json:"caPem"`
	Zones           []backend.Zone `json:"zones"`
	TokenID         string         `json:"tokenId"`
	Token           string         `json:"token,omitempty"`
	Generation      int64          `json:"generation,omitempty"`
	FirewallTokenID string         `json:"firewallTokenId,omitempty"`
	FirewallToken   string         `json:"firewallToken,omitempty"`
	BackupTokenID   string         `json:"backupTokenId,omitempty"`
	BackupToken     string         `json:"backupToken,omitempty"`
}

func TestRegistrationFileKeepsThePreDRSchema(t *testing.T) {
	r := newDRRegion(t)
	checkLaunch(t, r.register(true, nil))
	data, err := os.ReadFile(filepath.Join(r.state, registrationFile))
	checkLaunch(t, err)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var old preDRSnapshot
	if err := dec.Decode(&old); err != nil || old.Token != "fake-secret" {
		t.Fatalf("a pre-DR daemon refuses registration.json: %v\n%s", err, data)
	}
}

// region.yaml has no DR key: drStorage is registration data.
func TestRegionYAMLHasNoDRKey(t *testing.T) {
	if _, err := ParseRegion([]byte("read_only: true\ndr_storage: dr-pbs\n")); err == nil {
		t.Fatal("region.yaml took dr_storage")
	}
}

// A damaged dr.json never takes the region down: it serves, reports cold
// DR as not configured and logs why, without the token.
func TestDamagedDRFileKeepsTheRegionServing(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	for name, damage := range map[string]func(path string) error{
		"not JSON": func(path string) error { return os.WriteFile(path, []byte("{"+pbsSecret), 0o600) },
		"incomplete": func(path string) error {
			return os.WriteFile(path, []byte(`{"storage":"dr-pbs","token":"`+pbsSecret+`"}`), 0o600)
		},
		"readable by others": func(path string) error { return os.Chmod(path, 0o644) },
		"a symlink": func(path string) error {
			target := path + ".target"
			return errors.Join(os.Rename(path, target), os.Symlink(target, path))
		},
	} {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			r := newDRRegion(t)
			checkLaunch(t, r.register(true, nil))
			checkLaunch(t, damage(filepath.Join(r.state, drFile)))
			if got := r.coldDR(r.open()); got != resource.ColdDRNotConfigured {
				t.Fatalf("coldDr with a damaged dr.json: %q", got)
			}
			log := logs.String()
			if !strings.Contains(log, "dr.json is unreadable or invalid") || strings.Contains(log, pbsSecret) {
				t.Fatalf("log: %s", logs.String())
			}
		})
	}
}

func TestDeregistrationRemovesTheDRFile(t *testing.T) {
	r := newDRRegion(t)
	checkLaunch(t, r.register(true, nil))
	kept, err := os.ReadFile(filepath.Join(r.state, drFile))
	checkLaunch(t, err)
	req := []byte(`{"region":"pve-test-1","generation":1}`)
	removed, err := r.conn.Deregister(t.Context(), req)
	if !removed || err != nil {
		t.Fatalf("deregister: %v %v", removed, err)
	}
	absent(t, filepath.Join(r.state, drFile))
	absent(t, filepath.Join(r.state, registrationFile))
	// A daemon that does not know dr.json, an older one, removed the
	// registration and kept it; the console's retry at the same generation
	// removes it.
	writeFixture(t, filepath.Join(r.state, drFile), kept)
	removed, err = r.conn.Deregister(t.Context(), req)
	if !removed || err != nil {
		t.Fatalf("repeated deregister: %v %v", removed, err)
	}
	absent(t, filepath.Join(r.state, drFile))
}

// failAt makes conn fail the nth time it reaches stage.
func failAt(conn *Connection, stage string, nth int) {
	conn.step = func(s string) error {
		if s != stage {
			return nil
		}
		if nth--; nth == 0 {
			return errors.New("injected failure at " + s)
		}
		return nil
	}
}

// A registration that fails before registration.json is replaced keeps the
// committed DR state across a restart: it neither enables, changes nor
// disables DR. One that fails after it reports the new state.
func TestFailedRegistrationKeepsTheDRState(t *testing.T) {
	r := newDRRegion(t)
	restarted := func() *drState { return r.open().storedDR(t.Context()) }
	checkLaunch(t, r.register(false, nil))
	failAt(r.conn, "registration-rename", 1)
	if err := r.register(true, nil); err == nil {
		t.Fatal("a failing enable succeeded")
	}
	if dr := restarted(); dr != nil {
		t.Fatalf("a failed enable configured DR: %+v", dr)
	}

	r.conn.step = nil
	checkLaunch(t, r.register(true, nil))
	failAt(r.conn, "registration-rename", 1)
	if err := r.register(true, map[string]string{"drStorage": "dr-pbs2"}); err == nil {
		t.Fatal("a failing change succeeded")
	}
	if dr := restarted(); dr == nil || dr.Storage != "dr-pbs" {
		t.Fatalf("a failed change: %+v", dr)
	}
	failAt(r.conn, "registration-rename", 1)
	if err := r.register(false, nil); err == nil {
		t.Fatal("a failing disable succeeded")
	}
	if got := r.coldDR(r.open()); got != resource.ColdDRConfigured {
		t.Fatalf("a failed disable: %q", got)
	}

	// The second dr.json write drops the record of the old registration.
	failAt(r.conn, "dr-create", 2)
	if err := r.register(true, map[string]string{"drStorage": "dr-pbs2"}); err == nil {
		t.Fatal("a failing compaction succeeded")
	}
	if dr := restarted(); dr == nil || dr.Storage != "dr-pbs2" {
		t.Fatalf("a committed change: %+v", dr)
	}
	r.conn.step = nil
	checkLaunch(t, r.register(true, map[string]string{"drStorage": "dr-pbs2", "pbsToken": ""}))
	if dr := r.stored(); dr.Storage != "dr-pbs2" || dr.Token != pbsSecret {
		t.Fatalf("after the retry: %+v", dr)
	}
}

// dr.json applies only to the registration.json it was written with. A
// rewrite by another daemon, an older one included, makes a new file, even
// with the same bytes: DR is not configured, PBS is not asked, and dr.json and
// its token are removed.
func TestDRFollowsOnlyItsRegistrationFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rewrite func(t *testing.T, dir string, data []byte)
	}{
		{"rewritten", func(t *testing.T, dir string, data []byte) {
			t.Helper()
			checkLaunch(t, writeFileAtomic(dir, registrationFile, data, nil))
		}},
		{"removed and written again", func(t *testing.T, dir string, data []byte) {
			t.Helper()
			checkLaunch(t, os.Remove(filepath.Join(dir, registrationFile)))
			writeFixture(t, filepath.Join(dir, registrationFile), data)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newDRRegion(t)
			checkLaunch(t, r.register(true, nil))
			data, err := os.ReadFile(filepath.Join(r.state, registrationFile))
			checkLaunch(t, err)
			tc.rewrite(t, r.state, data)
			calls := r.pbs.calls
			if got := r.coldDR(r.open()); got != resource.ColdDRNotConfigured {
				t.Fatalf("coldDr after the rewrite: %q", got)
			}
			if r.pbs.calls != calls {
				t.Fatal("a reload contacted PBS")
			}
			absent(t, filepath.Join(r.state, drFile))
			if err := r.register(true, map[string]string{"pbsToken": ""}); errField(err) != "pbsToken" {
				t.Fatalf("the removed token was reused: %v", err)
			}
		})
	}
}

func TestPBSRegistrationInput(t *testing.T) {
	fp := strings.Repeat("ab:", 31) + "ab"
	for _, tc := range []struct {
		field, value, want string
	}{
		{"drStorage", "", "drStorage"},
		{"drStorage", "Dr", "drStorage"},
		{"pbsRepository", "pbs.example", "pbsRepository"},
		{"pbsRepository", "", "pbsRepository"},
		{"pbsNamespace", "", "pbsNamespace"},
		{"pbsNamespace", "a/../b", "pbsNamespace"},
		{"pbsFingerprint", "AB" + fp[2:], "pbsFingerprint"},
		{"pbsTokenId", "", "pbsTokenId"},
		{"pbsTokenId", "dr@pbs", "pbsTokenId"},
		{"pbsToken", "bad\nsecret", "pbsToken"},
		{"pbsToken", strings.Repeat("a", 513), "pbsToken"},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			fields := map[string]any{
				"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
				"pveApiUrls": []string{"https://pve1:8006"}, "caPem": anyCA(), "token": "fake-secret",
				"drStorage": "dr-pbs", "pbsRepository": "pbs.example:dr-store", "pbsNamespace": "vws/pve-test-1",
				"pbsFingerprint": fp, "pbsTokenId": pbsTokenID, "pbsToken": pbsSecret,
			}
			fields[tc.field] = tc.value
			data, err := json.Marshal(fields)
			checkLaunch(t, err)
			c := &Connection{region: "pve-test-1", dir: privateDir(t)}
			if err := c.Register(t.Context(), data); errField(err) != tc.want {
				t.Fatalf("invalid input: %v, want field %s", err, tc.want)
			}
		})
	}
	// A PBS token without the rest of the DR settings is refused.
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
		"pveApiUrls": []string{"https://pve1:8006"}, "caPem": anyCA(), "token": "fake-secret", "pbsToken": pbsSecret,
	})
	checkLaunch(t, err)
	c := &Connection{region: "pve-test-1", dir: privateDir(t)}
	if err := c.Register(t.Context(), data); errField(err) != "pbsTokenId" {
		t.Fatalf("token without settings: %v", err)
	}
}
