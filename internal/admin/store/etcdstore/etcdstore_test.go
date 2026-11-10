package etcdstore_test

import (
	"net/url"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore"
	"github.com/popododo0720/vws-console-api/internal/admin/store/storetest"
)

// startEtcd runs a one-member etcd on loopback ports the kernel picks.
func startEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "error"
	loopback := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	cfg.ListenClientUrls = []url.URL{loopback}
	cfg.AdvertiseClientUrls = []url.URL{loopback}
	cfg.ListenPeerUrls = []url.URL{loopback}
	cfg.AdvertisePeerUrls = []url.URL{loopback}
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
	c, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{e.Clients[0].Addr().String()},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestEtcdHonorsTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Backend { return etcdstore.New(startEtcd(t)) })
}
