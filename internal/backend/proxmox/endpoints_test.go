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
	s := scenario()
	s.Cluster = cluster
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return srv
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

func TestRegistrationReplacesAStateFileWithoutAddresses(t *testing.T) {
	pve := clusterServer(t, "test")
	c, state := openFixture(t)
	writeFixture(t, filepath.Join(state, registrationFile), []byte(`{"region":"pve-test-1","cluster_name":"test",`+
		`"tokenId":"vws@pve!inventory","token":"fake-secret"}`))
	// The admin push after an edit omits the token; the old file's token is reused.
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": []string{pve.URL}, "caPem": serverCA(pve),
		"tokenId": "vws@pve!inventory",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(t.Context(), data); err != nil {
		t.Fatalf("re-registration over a pre-pveApiUrls file: %v", err)
	}
	if _, err := c.Check(t.Context()); err != nil {
		t.Fatalf("check after re-registration: %v", err)
	}
}
