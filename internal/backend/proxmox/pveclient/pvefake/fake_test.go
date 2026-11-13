package pvefake_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

const (
	auditor    = "vws@pve!auditor"
	auditorKey = "00000000-0000-4000-8000-000000000001"
	poolA      = "vws@pve!pool-a"
	poolAKey   = "00000000-0000-4000-8000-000000000002"
)

func scenario(t *testing.T) pvefake.Scenario {
	t.Helper()
	s, err := pvefake.Load("testdata/default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func start(t *testing.T, s pvefake.Scenario) (*pvefake.Fake, *httptest.Server) {
	t.Helper()
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func client(t *testing.T, srv *httptest.Server, id, key string) *pveclient.Client {
	t.Helper()
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: id, Secret: pveclient.Secret(key), Backoff: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func status(err error) int {
	if he, ok := errors.AsType[*pveclient.HTTPError](err); ok {
		return he.Status
	}
	return 0
}

// TestServesClusterAndVMReads reads the cluster, node and VM config paths of
// pveclient with an auditor token and checks what the fixture holds.
func TestServesClusterAndVMReads(t *testing.T) {
	_, srv := start(t, scenario(t))
	c := client(t, srv, auditor, auditorKey)
	ctx := t.Context()
	vm := pveclient.VM{Node: "pve1", VMID: 100}
	checks := []struct {
		name string
		got  func() (any, error)
		want func(any) bool
	}{
		{"version", func() (any, error) { return c.Version(ctx) }, func(v any) bool {
			return v.(pveclient.Version).Version == "9.2.13"
		}},
		{"cluster status", func() (any, error) { return c.ClusterStatus(ctx) }, func(v any) bool {
			s := v.([]pveclient.ClusterStatus)
			return len(s) == 3 && s[0].Type == "cluster" && s[0].Quorate == 1 && s[1].Local == 1
		}},
		{"vm resources", func() (any, error) { return c.ClusterResources(ctx, pveclient.ResourceVM) }, func(v any) bool {
			r := v.([]pveclient.ClusterResource)
			return len(r) == 3 && r[0].ID == "qemu/100" && r[0].Pool == "vws-a" && r[2].Template == 1
		}},
		{"nodes", func() (any, error) { return c.Nodes(ctx) }, func(v any) bool {
			return len(v.([]pveclient.Node)) == 2
		}},
		{"config", func() (any, error) { return c.VMConfig(ctx, vm) }, func(v any) bool {
			cfg := v.(pveclient.VMConfig)
			return cfg.Name == "web-1" && len(cfg.Digest) == 40
		}},
	}
	for _, tc := range checks {
		got, err := tc.got()
		if err != nil || !tc.want(got) {
			t.Errorf("%s = %+v, %v", tc.name, got, err)
		}
	}
	var raw struct {
		Data map[string]any `json:"data"`
	}
	get(t, srv, "/nodes/pve1/qemu/100/config", &raw)
	if raw.Data["smbios1"] != "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10" {
		t.Errorf("config smbios1 = %v", raw.Data["smbios1"])
	}
}

func TestConfigNumericWireForms(t *testing.T) {
	s := scenario(t)
	for key, value := range map[string]string{
		"memory": "1024", "cores": "1", "sockets": "1", "balloon": "512", "agent": "1", "protection": "1",
	} {
		s.VMs[0].Config[key] = value
	}
	_, srv := start(t, s)
	var raw struct {
		Data map[string]any `json:"data"`
	}
	get(t, srv, "/nodes/pve1/qemu/100/config", &raw)
	for key, want := range map[string]any{
		"memory": "1024", "cores": "1", "sockets": "1", "balloon": "512", "agent": "1", "protection": float64(1),
	} {
		if raw.Data[key] != want {
			t.Errorf("%s = %#v, want %#v", key, raw.Data[key], want)
		}
	}
	get(t, srv, "/nodes/pve1/qemu/9000/config", &raw)
	if raw.Data["template"] != float64(1) {
		t.Fatalf("template = %#v", raw.Data["template"])
	}
}

func get(t *testing.T, srv *httptest.Server, path string, out any) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api2/json"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "PVEAPIToken="+auditor+"="+auditorKey)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// TestTokenACLsAreEnforced: a token with VM.Audit only through /pool/vws-a reads that pool's VM, gets 403
// for other VMs and /cluster/status, lists its VM without the pool and the nodes without stats, and
// /access/permissions answers its grants, the pool member at 0.
func TestTokenACLsAreEnforced(t *testing.T) {
	_, srv := start(t, scenario(t))
	c := client(t, srv, poolA, poolAKey)
	ctx := t.Context()
	if _, err := c.VMConfig(ctx, pveclient.VM{Node: "pve1", VMID: 100}); err != nil {
		t.Fatalf("config of a VM in the token's pool: %v", err)
	}
	for _, vm := range []pveclient.VM{{Node: "pve2", VMID: 101}, {Node: "pve2", VMID: 999}} {
		if _, err := c.VMConfig(ctx, vm); status(err) != http.StatusForbidden {
			t.Errorf("config of %d without VM.Audit = %v, want 403", vm.VMID, err)
		}
	}
	if _, err := c.ClusterStatus(ctx); status(err) != http.StatusForbidden {
		t.Errorf("cluster status without Sys.Audit = %v, want 403", err)
	}
	res, err := c.ClusterResources(ctx, "")
	if err != nil || len(res) != 3 || res[0].VMID != 100 || res[0].Pool != "" ||
		res[1].ID != "node/pve1" || res[1].MaxCPU != 0 {
		t.Errorf("resources = %+v, %v; want qemu/100 without pool, then both nodes without stats", res, err)
	}
	perms, err := c.AccessPermissions(ctx, "")
	want := pveclient.Permissions{"/pool/vws-a": {"VM.Audit": 1}, "/vms/100": {"VM.Audit": 0}}
	if err != nil || !reflect.DeepEqual(perms, want) {
		t.Errorf("permissions = %v, %v; want %v", perms, err, want)
	}
	if perms, err := c.AccessPermissions(ctx, "/vms/101"); err != nil || len(perms["/vms/101"]) != 0 {
		t.Errorf("permissions on /vms/101 = %v, %v; want none", perms, err)
	}
}

// TestDeeperACLReplacesInherited follows PVE: an entry on a deeper path
// replaces the inherited roles, NoAccess removes them, and one that does not
// propagate holds only on its own path and on the members of its pool.
func TestDeeperACLReplacesInherited(t *testing.T) {
	s := scenario(t)
	no := false
	s.Roles = append(s.Roles, pvefake.Role{ID: "NoAccess"})
	s.Tokens = append(s.Tokens, pvefake.Token{ID: "vws@pve!mixed", Secret: "k", ACL: []pvefake.ACE{
		{Path: "/", Role: "PVEAuditor"},
		{Path: "/vms/101", Role: "NoAccess"},
		{Path: "/nodes/pve1", Role: "VMReader"},
		{Path: "/sdn/zones/z1", Role: "VMReader"},
	}})
	s.Tokens[1].ACL[0].Propagate = &no
	s.Tokens[1].ACL = append(s.Tokens[1].ACL, pvefake.ACE{Path: "/vms", Role: "VMReader", Propagate: &no})
	_, srv := start(t, s)
	ctx := t.Context()
	mixed := client(t, srv, "vws@pve!mixed", "k")
	if _, err := mixed.VMConfig(ctx, pveclient.VM{Node: "pve2", VMID: 101}); status(err) != http.StatusForbidden {
		t.Errorf("NoAccess on /vms/101 = %v, want 403", err)
	}
	perms, err := mixed.AccessPermissions(ctx, "/nodes/pve1")
	if want := (pveclient.Permissions{"/nodes/pve1": {"VM.Audit": 1}}); err != nil || !reflect.DeepEqual(perms, want) {
		t.Errorf("VMReader on /nodes/pve1 under PVEAuditor on / = %v, %v; want %v", perms, err, want)
	}
	if perms, err := mixed.AccessPermissions(ctx, ""); err != nil || perms["/vms/101"] != nil || perms["/"] == nil {
		t.Errorf("permissions = %v, %v; want / and no NoAccess path", perms, err)
	}
	perms, err = client(t, srv, auditor, auditorKey).AccessPermissions(ctx, "")
	if err != nil || perms["/sdn/zones"]["Sys.Audit"] != 1 {
		t.Errorf("auditor permissions = %v, %v; want the ACL tree node /sdn/zones", perms, err)
	}
	pool := client(t, srv, poolA, poolAKey)
	if _, err := pool.VMConfig(ctx, pveclient.VM{Node: "pve1", VMID: 100}); err != nil {
		t.Errorf("a /pool/vws-a entry without propagate did not reach its member: %v", err)
	}
	if _, err := pool.VMConfig(ctx, pveclient.VM{Node: "pve2", VMID: 101}); status(err) != http.StatusForbidden {
		t.Errorf("a /vms entry without propagate reached /vms/101: %v", err)
	}
}

// TestClusterShapes sets multi-node, quorum loss, an offline node and a
// standalone node from a test.
func TestClusterShapes(t *testing.T) {
	f, srv := start(t, scenario(t))
	c := client(t, srv, auditor, auditorKey)
	ctx := t.Context()
	f.SetQuorate(false)
	if err := f.SetNodeOnline("pve2", false); err != nil {
		t.Fatal(err)
	}
	st, err := c.ClusterStatus(ctx)
	if err != nil || st[0].Nodes != 2 || st[0].Quorate != 0 || st[2].Online != 0 {
		t.Errorf("status after quorum loss = %+v, %v", st, err)
	}
	if _, err := c.VMConfig(ctx, pveclient.VM{Node: "pve2", VMID: 101}); status(err) != 595 {
		t.Errorf("call to an offline node = %v, want 595", err)
	}

	s := scenario(t)
	s.Cluster, s.Nodes, s.VMs = "", s.Nodes[:1], s.VMs[:1]
	_, alone := start(t, s)
	st, err = client(t, alone, auditor, auditorKey).ClusterStatus(ctx)
	if err != nil || len(st) != 1 || st[0].Type != "node" || st[0].Online != 1 {
		t.Errorf("standalone status = %+v, %v; want one node row and no cluster row", st, err)
	}
	var raw struct {
		Data []map[string]any `json:"data"`
	}
	if get(t, alone, "/cluster/status", &raw); raw.Data[0]["nodeid"] != 0.0 {
		t.Errorf("standalone nodeid = %v, want 0", raw.Data[0]["nodeid"])
	}
}

// TestRestartedFakeAnswersTheSame: a Fake built again from the same scenario
// answers the same digest, so a backend restarted over it reads the same VM,
// and editing the scenario after New does not change a running Fake.
func TestRestartedFakeAnswersTheSame(t *testing.T) {
	read := func(srv *httptest.Server) string {
		cfg, err := client(t, srv, auditor, auditorKey).VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Digest
	}
	s := scenario(t)
	_, srv := start(t, s)
	first := read(srv)
	s.VMs[0].Config["cores"], s.Tokens[0].Secret = "64", "edited-after-new"
	if again := read(srv); again != first {
		t.Errorf("an edit to the scenario after New changed digest %s to %s", first, again)
	}
	if _, restarted := start(t, scenario(t)); read(restarted) != first {
		t.Errorf("digest %s changed across a restart", first)
	}
}

// TestHostileCallsAreRefused: a bad secret, an unknown token, a bad vmid, an
// unknown path or resource type each get PVE's error, and a refused secret
// never shows in the answer.
func TestHostileCallsAreRefused(t *testing.T) {
	_, srv := start(t, scenario(t))
	ctx := t.Context()
	for _, tok := range [][2]string{{auditor, "wrong-secret-value"}, {"root@pam!x", auditorKey}} {
		_, err := client(t, srv, tok[0], tok[1]).Version(ctx)
		if status(err) != http.StatusUnauthorized || strings.Contains(err.Error(), tok[1]) {
			t.Errorf("token %s = %v, want 401 without the secret", tok[0], err)
		}
	}
	for path, want := range map[string]int{
		"/nodes/pve1/qemu/abc/config":       http.StatusBadRequest,
		"/nodes/pve1/qemu/101/config":       http.StatusInternalServerError,
		"/nodes/nope/qemu/100/config":       http.StatusInternalServerError,
		"/cluster/resources?type=lxc":       http.StatusBadRequest,
		"/nodes/pve1/qemu/100/status/start": http.StatusNotImplemented,
	} {
		if got := get(t, srv, path, nil); got != want {
			t.Errorf("GET %s = %d, want %d", path, got, want)
		}
	}
}

func TestNewRefusesABadScenario(t *testing.T) {
	cases := map[string]func(*pvefake.Scenario){
		"no version":        func(s *pvefake.Scenario) { s.Version = pvefake.Version{} },
		"vm on no node":     func(s *pvefake.Scenario) { s.VMs[0].Node = "pve9" },
		"repeated vmid":     func(s *pvefake.Scenario) { s.VMs[1].VMID = 100 },
		"unknown role":      func(s *pvefake.Scenario) { s.Tokens[0].ACL[0].Role = "Administrator" },
		"unclean acl path":  func(s *pvefake.Scenario) { s.Tokens[0].ACL[0].Path = "/vms/../" },
		"bad token id":      func(s *pvefake.Scenario) { s.Tokens[0].ID = "vws" },
		"nodes, no cluster": func(s *pvefake.Scenario) { s.Cluster = "" },
		"repeated token":    func(s *pvefake.Scenario) { s.Tokens[1].ID = s.Tokens[0].ID },
		"repeated role":     func(s *pvefake.Scenario) { s.Roles[1].ID = s.Roles[0].ID },
	}
	for name, edit := range cases {
		s := scenario(t)
		edit(&s)
		if _, err := pvefake.New(s); err == nil {
			t.Errorf("%s: New took it", name)
		}
	}
	if _, err := pvefake.Parse([]byte("version: {version: x, release: y}\nextra: 1\n")); err == nil {
		t.Error("Parse took an unknown key")
	}
}

func TestStorageAndSnapshotReads(t *testing.T) {
	s := scenario(t)
	s.VMs[0].Snapshots = []pvefake.Snapshot{{Name: "backup", Description: "saved", SnapTime: 1700000000}}
	s.Storages = []pvefake.Storage{{Node: "pve1", Name: "local", Content: []pvefake.StorageContent{
		{VolID: "local:vm-100-disk-0", Content: "images", Format: "qcow2", Size: 8 << 30, VMID: 100},
	}}}
	_, srv := start(t, s)
	s.VMs[0].Snapshots[0].Name = "changed"
	s.Storages[0].Content[0].Size = 1
	c := client(t, srv, auditor, auditorKey)
	snaps, err := c.Snapshots(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
	if err != nil || len(snaps) != 2 || snaps[0].Name != "current" || snaps[1].Name != "backup" {
		t.Fatalf("snapshots=%+v error=%v", snaps, err)
	}
	rows, err := c.StorageContent(t.Context(), "pve1", "local")
	if err != nil || len(rows) != 1 || rows[0].Format != "qcow2" || rows[0].Size != 8<<30 {
		t.Fatalf("storage=%+v error=%v", rows, err)
	}
	limited := client(t, srv, poolA, poolAKey)
	if _, err := limited.StorageContent(t.Context(), "pve1", "local"); status(err) != 403 {
		t.Fatalf("storage without Datastore.Audit: %v", err)
	}
	if _, err := limited.Snapshots(t.Context(), pveclient.VM{Node: "pve2", VMID: 101}); status(err) != 403 {
		t.Fatalf("snapshot without VM.Audit: %v", err)
	}
}

func TestPoolReadsIncludeEmptyAndVMPools(t *testing.T) {
	s := scenario(t)
	s.Pools = []string{"empty"}
	f, srv := start(t, s)
	s.Pools[0] = "changed-after-new"
	c := client(t, srv, auditor, auditorKey)
	for pool, want := range map[string]bool{"vws-a": true, "empty": true, "missing": false, "changed-after-new": false} {
		if got, err := c.Pool(t.Context(), pool); err != nil || got != want {
			t.Fatalf("pool %s = %t, %v, want %t", pool, got, err, want)
		}
	}
	if err := f.MoveVM(100, "new-pool"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Pool(t.Context(), "new-pool"); !got || err != nil {
		t.Fatalf("moved VM pool: %t %v", got, err)
	}
	limited := client(t, srv, poolA, poolAKey)
	if got, err := limited.Pool(t.Context(), "vws-a"); got || status(err) != 403 {
		t.Fatalf("pool without Pool.Audit: %t %v", got, err)
	}
	parsed, err := pvefake.Parse([]byte("pools: [empty, another]\n"))
	if err != nil || len(parsed.Pools) != 2 {
		t.Fatalf("scenario pools: %+v %v", parsed.Pools, err)
	}
}
