package proxmox

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	pbsTokenID = "dr@pbs!export"
	pbsSecret  = "pbs-read-secret-6f2c"
	drPath     = "/datastore/dr-store/vws/pve-test-1"
)

// pbsFake is a PBS at the boundary: it answers GET
// /api2/json/access/permissions for the tokens it knows, as PBS does, with
// the privileges each holds per ACL path.
type pbsFake struct {
	mu     sync.Mutex
	tokens map[string]map[string]map[string]bool // "id:secret" -> path -> privilege
	calls  int
}

func newPBSFake(t *testing.T) (*pbsFake, *httptest.Server) {
	t.Helper()
	f := &pbsFake{tokens: map[string]map[string]map[string]bool{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *pbsFake) grant(id, secret string, acl map[string][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := map[string]map[string]bool{}
	for path, privileges := range acl {
		held[path] = map[string]bool{}
		for _, p := range privileges {
			held[path][p] = true
		}
	}
	f.tokens[id+":"+secret] = held
}

func (f *pbsFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	credential, ok := strings.CutPrefix(r.Header.Get("Authorization"), "PBSAPIToken=")
	held, known := f.tokens[credential]
	if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/permissions" || !ok || !known {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": held})
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

var drReader = []string{"Datastore.Audit", "Datastore.Read"}

func TestPBSTokenScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		acl   map[string][]string
		check string
		want  string
	}{
		{name: "DatastoreReader on the namespace", acl: map[string][]string{drPath: drReader}},
		{name: "read only", acl: map[string][]string{drPath: {"Datastore.Read"}}},
		{name: "reader on a child namespace too", acl: map[string][]string{drPath: drReader, drPath + "/old": drReader}},
		{
			name: "backup privilege", acl: map[string][]string{drPath: append([]string{"Datastore.Backup"}, drReader...)},
			check: "pbs_privileges", want: "Datastore.Backup on " + drPath,
		},
		{
			name: "modify privilege", acl: map[string][]string{drPath: append([]string{"Datastore.Modify"}, drReader...)},
			check: "pbs_privileges", want: "Datastore.Modify",
		},
		{
			name: "reader on the whole datastore", acl: map[string][]string{"/datastore/dr-store": drReader, drPath: drReader},
			check: "pbs_privileges", want: "on /datastore/dr-store",
		},
		{
			name:  "reader on another namespace",
			acl:   map[string][]string{drPath: drReader, "/datastore/dr-store/other": drReader},
			check: "pbs_privileges", want: "on /datastore/dr-store/other",
		},
		{
			name: "a sibling with the same prefix", acl: map[string][]string{drPath: drReader, drPath + "x": drReader},
			check: "pbs_privileges", want: "on " + drPath + "x",
		},
		{
			name: "system audit", acl: map[string][]string{drPath: drReader, "/": {"Sys.Audit"}},
			check: "pbs_privileges", want: "Sys.Audit on /",
		},
		{
			name: "audit only", acl: map[string][]string{drPath: {"Datastore.Audit"}},
			check: "pbs_privileges", want: "lacks Datastore.Read on " + drPath,
		},
		{name: "no grant", acl: map[string][]string{}, check: "pbs_privileges", want: "lacks Datastore.Read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newPBSFake(t)
			f.grant(pbsTokenID, pbsSecret, tc.acl)
			err := checkPBS(t.Context(), pbsTargetFor(srv, pbsTokenID, pbsSecret), RegionConfig{DRStorage: "local"})
			var sc *selfCheckError
			switch {
			case tc.check == "":
				checkLaunch(t, err)
			case !errors.As(err, &sc) || sc.check != tc.check || !strings.Contains(err.Error(), tc.want):
				t.Fatalf("checkPBS = %v, want %s naming %q", err, tc.check, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), pbsSecret) {
				t.Fatalf("the diagnostic carries the token: %v", err)
			}
		})
	}
}

func TestPBSConnectionChecks(t *testing.T) {
	f, srv := newPBSFake(t)
	f.grant(pbsTokenID, pbsSecret, map[string][]string{drPath: drReader})
	for _, tc := range []struct {
		name   string
		target func(*pbsTarget)
		config RegionConfig
		check  string
	}{
		{name: "another certificate", target: func(p *pbsTarget) {
			p.fingerprint = strings.Repeat("00:", 31) + "00"
		}, config: RegionConfig{DRStorage: "local"}, check: "pbs_connection"},
		{
			name: "a wrong secret", target: func(p *pbsTarget) { p.token = "other-secret" },
			config: RegionConfig{DRStorage: "local"}, check: "pbs_connection",
		},
		{name: "no dr_storage", target: func(*pbsTarget) {}, check: "dr_storage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pbsTargetFor(srv, pbsTokenID, pbsSecret)
			tc.target(p)
			err := checkPBS(t.Context(), p, tc.config)
			var sc *selfCheckError
			if !errors.As(err, &sc) || sc.check != tc.check {
				t.Fatalf("checkPBS = %v, want %s", err, tc.check)
			}
			if strings.Contains(err.Error(), pbsSecret) || strings.Contains(err.Error(), "other-secret") {
				t.Fatalf("the diagnostic carries the token: %v", err)
			}
		})
	}
}

func TestPBSRegistration(t *testing.T) {
	dir := privateDir(t)
	f, err := pvefake.New(scenario())
	checkLaunch(t, err)
	pve := httptest.NewTLSServer(f)
	defer pve.Close()
	pbs, pbsSrv := newPBSFake(t)
	pbs.grant(pbsTokenID, pbsSecret, map[string][]string{drPath: drReader})
	pbs.grant("dr@pbs!broad", "broad-secret",
		map[string][]string{drPath: append([]string{"Datastore.Backup"}, drReader...)})
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\ndr_storage: local\n"))
	state := filepath.Join(dir, "state")
	reg := filepath.Join(state, registrationFile)
	open := func() *Connection {
		conn, err := Open(config, "pve-test-1", state)
		checkLaunch(t, err)
		return conn
	}
	conn := open()
	repository := strings.TrimPrefix(pbsSrv.URL, "https://") + ":dr-store"
	fingerprint := pbsServerFingerprint(pbsSrv)
	register := func(fields map[string]string) error {
		urls, ca := target(t, pve)
		input := map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
			"pveApiUrls": urls, "caPem": ca, "token": "fake-secret",
			"pbsRepository": repository, "pbsNamespace": "vws/pve-test-1", "pbsFingerprint": fingerprint,
		}
		for k, v := range fields {
			if v == "" {
				delete(input, k)
			} else {
				input[k] = v
			}
		}
		data, err := json.Marshal(input)
		checkLaunch(t, err)
		return conn.Register(t.Context(), data)
	}
	coldDR := func(conn *Connection) string {
		t.Helper()
		b, err := conn.Check(t.Context())
		checkLaunch(t, err)
		caps, err := b.RegionCapabilities(t.Context(), "pve-test-1")
		checkLaunch(t, err)
		return caps.Features.ColdDR
	}

	// A token that can do more than read the DR namespace is refused, and nothing is stored.
	err = register(map[string]string{"pbsTokenId": "dr@pbs!broad", "pbsToken": "broad-secret"})
	_, statErr := os.Stat(reg)
	if err == nil || resource.AsError(err).Message != "registration self-check failed: pbs_privileges" ||
		!os.IsNotExist(statErr) {
		t.Fatalf("over-privileged PBS token: %v, state: %v", err, statErr)
	}
	if strings.Contains(err.Error(), "broad-secret") {
		t.Fatalf("the refusal carries the token: %v", err)
	}
	// A first registration has no stored secret to reuse.
	if err := register(map[string]string{"pbsTokenId": pbsTokenID}); errField(err) != "pbsToken" {
		t.Fatalf("first PBS registration without secret: %v", err)
	}
	// The read-only token is accepted; a restart reports DR configured from the state file alone.
	checkLaunch(t, register(map[string]string{"pbsTokenId": pbsTokenID, "pbsToken": pbsSecret}))
	if got := coldDR(open()); got != resource.ColdDRConfigured {
		t.Fatalf("coldDr after PBS registration: %q", got)
	}
	calls := pbs.calls
	pbsSrv.Close()
	if got := coldDR(open()); got != resource.ColdDRConfigured {
		t.Fatalf("a restart with PBS down: %q", got)
	}
	if pbs.calls != calls {
		t.Fatal("a reload contacted PBS")
	}
	stored, err := os.ReadFile(reg)
	checkLaunch(t, err)
	var snapshot registrationSnapshot
	checkLaunch(t, json.Unmarshal(stored, &snapshot))
	if snapshot.PBSToken != pbsSecret || snapshot.PBSRepository != repository || snapshot.PBSFingerprint != fingerprint {
		t.Fatalf("stored PBS settings: %+v", snapshot)
	}
}

func TestPBSSecretReuse(t *testing.T) {
	dir := privateDir(t)
	f, err := pvefake.New(scenario())
	checkLaunch(t, err)
	pve := httptest.NewTLSServer(f)
	defer pve.Close()
	pbs, pbsSrv := newPBSFake(t)
	pbs.grant(pbsTokenID, pbsSecret, map[string][]string{drPath: drReader})
	other, otherSrv := newPBSFake(t)
	other.grant(pbsTokenID, pbsSecret, map[string][]string{drPath: drReader})
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\ndr_storage: local\n"))
	conn, err := Open(config, "pve-test-1", filepath.Join(dir, "state"))
	checkLaunch(t, err)
	repository := strings.TrimPrefix(pbsSrv.URL, "https://") + ":dr-store"
	fingerprint := pbsServerFingerprint(pbsSrv)
	register := func(fields map[string]string) error {
		urls, ca := target(t, pve)
		input := map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
			"pveApiUrls": urls, "caPem": ca, "token": "fake-secret",
			"pbsRepository": repository, "pbsNamespace": "vws/pve-test-1", "pbsFingerprint": fingerprint,
			"pbsTokenId": pbsTokenID,
		}
		for k, v := range fields {
			input[k] = v
		}
		data, err := json.Marshal(input)
		checkLaunch(t, err)
		return conn.Register(t.Context(), data)
	}
	checkLaunch(t, register(map[string]string{"pbsToken": pbsSecret}))
	// The same repository and fingerprint reuse the stored secret, which PBS checks again.
	calls := pbs.calls
	checkLaunch(t, register(nil))
	if pbs.calls != calls+1 {
		t.Fatalf("reuse did not check the stored token: %d -> %d calls", calls, pbs.calls)
	}
	// A namespace is no destination: the token goes to the same PBS.
	pbs.grant(pbsTokenID, pbsSecret, map[string][]string{"/datastore/dr-store/vws/other": drReader})
	checkLaunch(t, register(map[string]string{"pbsNamespace": "vws/other"}))
	for name, fields := range map[string]map[string]string{
		"another repository": {"pbsRepository": strings.TrimPrefix(otherSrv.URL, "https://") + ":dr-store"},
		"another datastore":  {"pbsRepository": strings.TrimPrefix(pbsSrv.URL, "https://") + ":dr-other"},
		// httptest servers share one certificate, so this fingerprint names no server.
		"another fingerprint": {"pbsFingerprint": strings.Repeat("ab:", 31) + "ab"},
		"another token":       {"pbsTokenId": "dr@pbs!other"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := pbs.calls + other.calls
			if err := register(fields); errField(err) != "pbsToken" {
				t.Fatalf("reuse for %s: %v", name, err)
			}
			if pbs.calls+other.calls != calls {
				t.Fatal("the stored secret was sent to a new destination")
			}
		})
	}
}

// A region without PBS settings registers as before and reports cold DR as
// not configured, with or without dr_storage.
func TestRegionWithoutPBSReportsColdDRNotConfigured(t *testing.T) {
	for _, yaml := range []string{"read_only: true\n", "read_only: true\ndr_storage: local\n"} {
		dir := privateDir(t)
		f, err := pvefake.New(scenario())
		checkLaunch(t, err)
		pve := httptest.NewTLSServer(f)
		config := filepath.Join(dir, "region.yaml")
		writeFixture(t, config, []byte(yaml))
		conn, err := Open(config, "pve-test-1", filepath.Join(dir, "state"))
		checkLaunch(t, err)
		urls, ca := target(t, pve)
		data, err := json.Marshal(map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
			"pveApiUrls": urls, "caPem": ca, "token": "fake-secret",
		})
		checkLaunch(t, err)
		checkLaunch(t, conn.Register(t.Context(), data))
		stored, err := os.ReadFile(filepath.Join(dir, "state", registrationFile))
		checkLaunch(t, err)
		if strings.Contains(string(stored), "pbs") {
			t.Fatalf("state of a region without PBS: %s", stored)
		}
		b, err := conn.Check(t.Context())
		checkLaunch(t, err)
		caps, err := b.RegionCapabilities(t.Context(), "pve-test-1")
		checkLaunch(t, err)
		if caps.Features.ColdDR != resource.ColdDRNotConfigured || b.pbs != nil {
			t.Fatalf("%q: coldDr %q", yaml, caps.Features.ColdDR)
		}
		pve.Close()
	}
}

func TestPBSRegistrationInput(t *testing.T) {
	fp := strings.Repeat("ab:", 31) + "ab"
	for _, tc := range []struct {
		field, value, want string
	}{
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
				"pbsRepository": "pbs.example:dr-store", "pbsNamespace": "vws/pve-test-1", "pbsFingerprint": fp,
				"pbsTokenId": pbsTokenID, "pbsToken": pbsSecret,
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
	// A PBS token without the rest of the PBS settings is refused.
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

func TestUnknownDRStorageFailsTheSelfCheck(t *testing.T) {
	client, _ := serve(t, scenario())
	_, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true, DRStorage: "missing"})
	var sc *selfCheckError
	if !errors.As(err, &sc) || sc.check != "dr_storage" {
		t.Fatalf("unknown dr_storage: %v", err)
	}
}
