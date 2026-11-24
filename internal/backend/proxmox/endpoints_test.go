package proxmox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// serverCA is the PEM of the certificate a httptest TLS server presents.
func serverCA(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// anyCA is a valid CA bundle for tests that never complete a TLS handshake.
var anyCA = sync.OnceValue(func() string {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	return serverCA(srv)
})

// target returns the registration fields that point at srv.
func target(t *testing.T, srv *httptest.Server) (urls []string, caPEM string) {
	t.Helper()
	if srv.TLS == nil {
		return []string{srv.URL}, anyCA()
	}
	return []string{srv.URL}, serverCA(srv)
}

// foreignCA is a valid CA that signed none of the httptest servers.
func foreignCA(t *testing.T) string {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 7)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		Subject: pkix.Name{CommonName: "foreign CA"}, SerialNumber: big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func clusterServer(t *testing.T, cluster string) *httptest.Server {
	t.Helper()
	srv, _ := clusterFake(t, cluster)
	return srv
}

func clusterFake(t *testing.T, cluster string) (*httptest.Server, *pvefake.Fake) {
	t.Helper()
	s := scenario()
	s.Cluster = cluster
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return srv, f
}

func openFixture(t *testing.T) (*Connection, string) {
	t.Helper()
	dir := privateDir(t)
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "state")
	c, err := Open(config, "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, state
}

func registerBody(t *testing.T, urls []string, ca string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": urls, "caPem": ca,
		"tokenId": "vws@pve!inventory", "token": "fake-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRegistrationRejectsAddressesOfDifferentClusters(t *testing.T) {
	first, same, other := clusterServer(t, "test"), clusterServer(t, "test"), clusterServer(t, "elsewhere")
	closed := httptest.NewTLSServer(nil)
	closedURL := closed.URL
	closed.Close()
	for _, tc := range []struct {
		name string
		urls []string
		want resource.Code
	}{
		{"second address is another cluster", []string{first.URL, other.URL}, resource.CodeConflict},
		{"third address is another cluster", []string{first.URL, same.URL, other.URL}, resource.CodeConflict},
		{"first address is another cluster", []string{other.URL, first.URL}, resource.CodeConflict},
		{"second address is unreachable", []string{first.URL, closedURL}, resource.CodeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, state := openFixture(t)
			err := c.Register(t.Context(), registerBody(t, tc.urls, serverCA(first)))
			if err == nil || resource.AsError(err).Code != tc.want {
				t.Fatalf("Register = %v, want code %s", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(state, registrationFile)); !os.IsNotExist(err) {
				t.Fatalf("a refused registration reached the state file: %v", err)
			}
		})
	}
	c, state := openFixture(t)
	urls := []string{first.URL, same.URL}
	if err := c.Register(t.Context(), registerBody(t, urls, serverCA(first))); err != nil {
		t.Fatalf("addresses of one cluster: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(state, registrationFile))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := decodeRegistration(data)
	if err != nil || !reflect.DeepEqual(stored.PVEAPIURLs, urls) || stored.CAPEM != serverCA(first) {
		t.Fatalf("stored registration: %+v %v", stored, err)
	}
	restarted, err := Open(filepath.Join(filepath.Dir(state), "region.yaml"), "pve-test-1", state)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Check(t.Context()); err != nil {
		t.Fatalf("restart without re-registration: %v", err)
	}
}

func TestRegistrationTrustsOnlyItsOwnCA(t *testing.T) {
	pve := clusterServer(t, "test")
	urls := []string{pve.URL}
	for name, ca := range map[string]string{"foreign CA": foreignCA(t), "empty": "", "not PEM": "bad"} {
		t.Run(name, func(t *testing.T) {
			c, state := openFixture(t)
			if err := c.Register(t.Context(), registerBody(t, urls, ca)); err == nil {
				t.Fatal("registered a server the CA did not sign")
			}
			if _, err := os.Stat(filepath.Join(state, registrationFile)); !os.IsNotExist(err) {
				t.Fatalf("a refused registration reached the state file: %v", err)
			}
		})
	}
	c, _ := openFixture(t)
	if err := c.Register(t.Context(), registerBody(t, urls, serverCA(pve))); err != nil {
		t.Fatal(err)
	}
	// A changed CA is used by the next check; the old client is not kept.
	snapshot, _, err := c.registration()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.CAPEM = foreignCA(t)
	if _, err := c.check(t.Context(), snapshot); err == nil {
		t.Fatal("check kept trusting the previous CA")
	}
}

func TestRegistrationWithoutAddressesIsNotReady(t *testing.T) {
	c, state := openFixture(t)
	writeFixture(t, filepath.Join(state, registrationFile), []byte(`{"region":"pve-test-1","cluster_name":"test",`+
		`"tokenId":"vws@pve!inventory","token":"fake-secret"}`))
	_, err := c.Check(t.Context())
	if err == nil || !strings.Contains(err.Error(), "register the region again") ||
		strings.Contains(err.Error(), "fake-secret") {
		t.Fatalf("pre-pveApiUrls state file: %v", err)
	}
}

func TestConnectionTestChecksEveryAddress(t *testing.T) {
	first, same, other := clusterServer(t, "test"), clusterServer(t, "test"), clusterServer(t, "elsewhere")
	for _, tc := range []struct {
		name string
		urls []string
		want resource.ConnectionResult
	}{
		{"one cluster", []string{first.URL, same.URL}, resource.ConnectionPass},
		{"another cluster last", []string{first.URL, other.URL}, resource.ConnectionFail},
		{"another cluster first", []string{other.URL, first.URL}, resource.ConnectionFail},
	} {
		steps := TestConnection(t.Context(), ConnectionConfig{
			URLs: tc.urls, CAPEM: serverCA(first), ClusterName: "test",
			TokenID: "vws@pve!inventory", TokenSecret: "fake-secret",
		})
		if len(steps) != 4 || steps[2].Name != "cluster_name" || steps[2].Result != tc.want {
			t.Errorf("%s: %+v, want cluster_name %s", tc.name, steps, tc.want)
		}
	}
	steps := TestConnection(t.Context(), ConnectionConfig{CAPEM: serverCA(first), ClusterName: "test"})
	if steps[0].Result != resource.ConnectionFail {
		t.Fatalf("no address: %+v", steps)
	}
}

func registerFields(t *testing.T, urls []string, ca string, token string) []byte {
	t.Helper()
	fields := map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": urls, "caPem": ca,
		"tokenId": "vws@pve!inventory",
	}
	if token != "" {
		fields["token"] = token
	}
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRegistrationReplacesAStateFileWithoutAddresses(t *testing.T) {
	pve, fake := clusterFake(t, "test")
	c, state := openFixture(t)
	writeFixture(t, filepath.Join(state, registrationFile), []byte(`{"region":"pve-test-1","cluster_name":"test",`+
		`"tokenId":"vws@pve!inventory","token":"fake-secret"}`))
	// Legacy state records no destination, so the stored secret is not sent anywhere.
	err := c.Register(t.Context(), registerFields(t, []string{pve.URL}, serverCA(pve), ""))
	if e := resource.AsError(err); err == nil || e.Code != resource.CodeInvalidArgument || e.Field != "token" {
		t.Fatalf("legacy state with the token omitted: %v", err)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Fatalf("legacy state: %d requests reached PVE", n)
	}
	if err := c.Register(t.Context(), registerFields(t, []string{pve.URL}, serverCA(pve), "fake-secret")); err != nil {
		t.Fatalf("re-registration with the secret: %v", err)
	}
	if _, err := c.Check(t.Context()); err != nil {
		t.Fatalf("check after re-registration: %v", err)
	}
}

func TestOmittedTokenIsReusedOnlyForTheSameTrust(t *testing.T) {
	a, fa := clusterFake(t, "test")
	b, fb := clusterFake(t, "test")
	extra, fe := clusterFake(t, "test")
	requests := func() int { return len(fa.Requests()) + len(fb.Requests()) + len(fe.Requests()) }
	c, _ := openFixture(t)
	ca := serverCA(a)
	if err := c.Register(t.Context(), registerFields(t, []string{a.URL, b.URL}, ca, "fake-secret")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"changed CA":       registerFields(t, []string{a.URL, b.URL}, foreignCA(t), ""),
		"added address":    registerFields(t, []string{a.URL, b.URL, extra.URL}, ca, ""),
		"replaced address": registerFields(t, []string{extra.URL}, ca, ""),
	} {
		before := requests()
		err := c.Register(t.Context(), body)
		if e := resource.AsError(err); err == nil || e.Code != resource.CodeInvalidArgument || e.Field != "token" {
			t.Errorf("%s: %v, want 400 on token", name, err)
		}
		if n := requests() - before; n != 0 {
			t.Errorf("%s: %d requests reached PVE", name, n)
		}
	}
	// In order: the subset narrows the stored set, so it goes last.
	for _, tc := range []struct {
		name string
		urls []string
	}{{"unchanged", []string{a.URL, b.URL}}, {"subset", []string{b.URL}}} {
		if err := c.Register(t.Context(), registerFields(t, tc.urls, ca, "")); err != nil {
			t.Errorf("%s with the token omitted: %v", tc.name, err)
		}
	}
	if _, err := c.Check(t.Context()); err != nil {
		t.Fatalf("stored secret was lost: %v", err)
	}
}

func TestStandaloneNodeCannotJoinAnAddressList(t *testing.T) {
	member, alone := clusterServer(t, "test"), clusterServer(t, "")
	second := clusterServer(t, "test")
	for name, urls := range map[string][]string{
		"standalone last":  {member.URL, alone.URL},
		"standalone first": {alone.URL, member.URL},
		"two standalone":   {alone.URL, clusterServer(t, "").URL},
	} {
		c, state := openFixture(t)
		err := c.Register(t.Context(), registerBody(t, urls, serverCA(member)))
		if e := resource.AsError(err); err == nil || e.Code != resource.CodeConflict {
			t.Errorf("%s: %v, want conflict", name, err)
		}
		if _, err := os.Stat(filepath.Join(state, registrationFile)); !os.IsNotExist(err) {
			t.Errorf("%s: a refused registration reached the state file", name)
		}
	}
	c, _ := openFixture(t)
	if err := c.Register(t.Context(), registerBody(t, []string{alone.URL}, serverCA(alone))); err != nil {
		t.Fatalf("single standalone address: %v", err)
	}
	if err := c.Register(t.Context(), registerBody(t, []string{member.URL, second.URL}, serverCA(member))); err != nil {
		t.Fatalf("clustered list: %v", err)
	}
	for name, tc := range map[string]struct {
		urls []string
		want resource.ConnectionResult
	}{
		"single standalone": {[]string{alone.URL}, resource.ConnectionPass},
		"mixed":             {[]string{member.URL, alone.URL}, resource.ConnectionFail},
		"standalone first":  {[]string{alone.URL, member.URL}, resource.ConnectionFail},
	} {
		steps := TestConnection(t.Context(), ConnectionConfig{
			URLs: tc.urls, CAPEM: serverCA(member), ClusterName: "test",
			TokenID: "vws@pve!inventory", TokenSecret: "fake-secret",
		})
		if steps[2].Result != tc.want {
			t.Errorf("connection test %s: %+v, want cluster_name %s", name, steps, tc.want)
		}
	}
}

func TestOmittedWriteTokensGoOnlyToStoredAddresses(t *testing.T) {
	var servers []*httptest.Server
	var fakes []*pvefake.Fake
	for range 2 {
		f, err := pvefake.New(backupScenario())
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(f)
		t.Cleanup(srv.Close)
		servers, fakes = append(servers, srv), append(fakes, f)
	}
	a, b := servers[0], servers[1]
	requests := func() int { return len(fakes[0].Requests()) + len(fakes[1].Requests()) }
	dir := privateDir(t)
	writeFixture(t, filepath.Join(dir, "region.yaml"),
		[]byte("read_only: false\npools: {project: managed, nested: parent/child}\n"))
	c, err := Open(filepath.Join(dir, "region.yaml"), "pve-test-1", filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ca := serverCA(a)
	body := func(urls []string, withSecrets, writeTokens bool) []byte {
		fields := map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": urls, "caPem": ca,
			"tokenId": "vws@pve!inventory",
		}
		if writeTokens {
			fields["firewallTokenId"], fields["backupTokenId"] = "vws@pve!firewall", "vws@pve!backup"
		}
		if withSecrets {
			fields["token"], fields["firewallToken"], fields["backupToken"] = "fake-secret", firewallSecret, backupSecret
			if !writeTokens {
				delete(fields, "firewallToken")
				delete(fields, "backupToken")
			}
		}
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := c.Register(t.Context(), body([]string{a.URL, b.URL}, true, true)); err != nil {
		t.Fatal(err)
	}
	// Failover sends every token to every address of the list, so an omitted
	// write secret is reused for any subset of the stored addresses.
	// In order: dropping an address narrows the stored set, so it goes last.
	for _, tc := range []struct {
		name string
		urls []string
	}{{"reordered", []string{b.URL, a.URL}}, {"first dropped", []string{b.URL}}} {
		if err := c.Register(t.Context(), body(tc.urls, false, true)); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A new address would receive a secret it never held.
	c3 := httptest.NewTLSServer(fakes[0])
	t.Cleanup(c3.Close)
	before := requests()
	err = c.Register(t.Context(), body([]string{a.URL, b.URL, c3.URL}, false, true))
	if e := resource.AsError(err); err == nil || e.Code != resource.CodeInvalidArgument || e.Field != "token" {
		t.Errorf("new address: %v, want 400 on token", err)
	}
	if n := requests() - before; n != 0 {
		t.Errorf("%d requests reached PVE", n)
	}
}

// An unchanged registration at a new generation keeps the serving backend, so
// the daemon keeps its quorum gate and consoles; a changed one serves its own
// newly checked backend, which Check then returns (vws-console-api#1077).
func TestRegistrationKeepsTheBackendOfAnUnchangedState(t *testing.T) {
	pve, _ := clusterFake(t, "test")
	c, _ := openFixture(t)
	ca := serverCA(pve)
	at := func(generation int, zones string) []byte {
		var fields map[string]any
		if err := json.Unmarshal(registerFields(t, []string{pve.URL}, ca, "fake-secret"), &fields); err != nil {
			t.Fatal(err)
		}
		fields["generation"] = generation
		fields["zones"] = json.RawMessage(zones)
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first, err := c.RegisterBackend(t.Context(), at(1, `[]`))
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.RegisterBackend(t.Context(), at(2, `[]`))
	if err != nil || again != first {
		t.Fatalf("unchanged registration replaced the backend: %v", err)
	}
	changed, err := c.RegisterBackend(t.Context(), at(3, `[{"letter":"a","nodes":["pve1"]}]`))
	if err != nil || changed == first {
		t.Fatalf("changed registration kept the old backend: %v", err)
	}
	if checked, err := c.Check(t.Context()); err != nil || checked != changed {
		t.Fatalf("Check after a changed registration: %v", err)
	}
}
