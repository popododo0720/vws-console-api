package etcdstore_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore"
	"github.com/popododo0720/vws-console-api/internal/admin/store/storetest"
	"github.com/popododo0720/vws-console-api/internal/globalconfig"
)

// startEtcd runs a one-member etcd on loopback ports the kernel picks.
func startEtcd(t *testing.T) *clientv3.Client {
	c, _ := startEtcdWithTLS(t, false)
	return c
}

func startEtcdWithTLS(t *testing.T, secure bool) (*clientv3.Client, string) {
	t.Helper()
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "error"
	loopback := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	if secure {
		loopback.Scheme = "https"
		cfg.ClientAutoTLS = true
	}
	cfg.ListenClientUrls = []url.URL{loopback}
	cfg.AdvertiseClientUrls = []url.URL{loopback}
	cfg.ListenPeerUrls = []url.URL{loopback}
	cfg.AdvertisePeerUrls = []url.URL{loopback}
	if secure {
		peer := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
		cfg.ListenPeerUrls = []url.URL{peer}
		cfg.AdvertisePeerUrls = []url.URL{peer}
	}
	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("etcd did not become ready")
	}
	var tlsConfig *tls.Config
	caFile := ""
	if secure {
		caFile = e.Config().ClientTLSInfo.CertFile
		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("invalid auto TLS certificate")
		}
		tlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	c, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{loopback.Scheme + "://" + e.Clients[0].Addr().String()},
		TLS:         tlsConfig,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, caFile
}

func TestEtcdHonorsTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Backend { return etcdstore.New(startEtcd(t)) })
}

func TestOpenRegistry(t *testing.T) {
	c, caFile := startEtcdWithTLS(t, true)
	g, closeRegistry, err := etcdstore.Open(t.Context(), globalconfig.IAM{
		EtcdEndpoints: c.Endpoints(), TLS: globalconfig.TLSFiles{CAFile: caFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeRegistry(); err != nil {
			t.Error(err)
		}
	})
	v, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-lab-1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Regions().Get(t.Context(), v.Name)
	if err != nil || got.Version != v.Version {
		t.Fatalf("read version: %+v %v", got, err)
	}
	if _, _, err := etcdstore.Open(t.Context(), globalconfig.IAM{
		EtcdEndpoints: c.Endpoints(), TLS: globalconfig.TLSFiles{CAFile: "/nonexistent/qa-ca.pem"},
	}); err == nil {
		t.Fatal("invalid CA accepted")
	}
	if _, _, err := etcdstore.Open(t.Context(), globalconfig.IAM{}); err == nil {
		t.Fatal("missing endpoints accepted")
	}
}
