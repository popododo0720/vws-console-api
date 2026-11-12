// Package etcdtest starts a TLS registry boundary for integration tests.
package etcdtest

import (
	"net/url"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"

	"github.com/popododo0720/vws-console-api/internal/globalconfig"
)

// Start returns bootstrap settings for a one-member TLS etcd server.
func Start(t testing.TB) globalconfig.IAM {
	t.Helper()
	cfg := embed.NewConfig()
	cfg.Dir, cfg.LogLevel, cfg.ClientAutoTLS = t.TempDir(), "error", true
	client := url.URL{Scheme: "https", Host: "127.0.0.1:0"}
	peer := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{client}, []url.URL{client}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{peer}, []url.URL{peer}
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
	return globalconfig.IAM{
		EtcdEndpoints: []string{"https://" + e.Clients[0].Addr().String()},
		TLS:           globalconfig.TLSFiles{CAFile: e.Config().ClientTLSInfo.CertFile},
	}
}
