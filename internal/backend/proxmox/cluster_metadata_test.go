package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestClusterMetadataFollowsLeaseAndQuorum(t *testing.T) {
	leader, fake, clock := testLeader(t, scenario())
	acquireLeader(t, leader)
	b := leader.backend
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	caller := resource.Caller{Account: account}
	svc := cloud.New(cloud.Config{
		Capabilities: b, Regions: backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: b.region}}, nil),
	})
	check := func(wantLeader string, quorum bool, state string) {
		t.Helper()
		status, err := b.Status(t.Context())
		if err != nil || status.Quorate != quorum || status.PVERelease != "9.2" {
			t.Fatalf("status: %+v %v", status, err)
		}
		if wantLeader == "" && status.Leader != nil ||
			wantLeader != "" && (status.Leader == nil || *status.Leader != wantLeader) {
			t.Fatalf("status leader: %+v; want %q", status.Leader, wantLeader)
		}
		doc, err := b.RegionCapabilities(t.Context(), b.region)
		if err != nil || doc.Cluster == nil || doc.Cluster.Name != "test" ||
			doc.Cluster.Leader != wantLeader || doc.Cluster.Quorate != quorum || doc.Cluster.PVERelease != "9.2" {
			t.Fatalf("capabilities: %+v %v", doc.Cluster, err)
		}
		regions, err := svc.Regions(t.Context(), caller)
		if err != nil || len(regions) != 1 || regions[0].State != state {
			t.Fatalf("regions: %+v %v", regions, err)
		}
	}
	check("pve1", true, "available")
	lease := leaderLease{Node: "pve2", Term: 2, Until: clock.now().Add(20 * time.Second)}
	data, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.PMXCFS().WriteFile(leaderPath, data); err != nil {
		t.Fatal(err)
	}
	if err := leader.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	check("pve2", true, "available")
	fake.SetQuorate(false)
	leader.checkQuorum(t.Context())
	check("pve2", false, "degraded")
	clock.advance(20 * time.Second)
	check("", false, "degraded")
	fake.SetQuorate(true)
	leader.checkQuorum(t.Context())
	leader.read = func(string) ([]byte, error) { return nil, errors.New("lease read failed") }
	if err := leader.renew(t.Context()); err == nil {
		t.Fatal("lease read unexpectedly succeeded")
	}
	check("", true, "degraded")
}

func TestClusterVersionFailureKeepsCapabilities(t *testing.T) {
	fake, err := pvefake.New(scenario())
	if err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() && r.URL.Path == "/api2/json/version" {
			<-r.Context().Done()
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer srv.Close()
	client, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory", Secret: "fake-secret", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	start := time.Now()
	doc, err := b.RegionCapabilities(t.Context(), b.region)
	if err != nil || doc.Cluster == nil || !doc.Cluster.Quorate || doc.Cluster.PVERelease != "" ||
		time.Since(start) > 3*time.Second {
		t.Fatalf("version failure: %+v %v after %s", doc.Cluster, err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.RegionCapabilities(ctx, b.region); err == nil {
		t.Fatal("canceled capabilities succeeded")
	}
	fail.Store(false)
	doc, err = b.RegionCapabilities(t.Context(), b.region)
	if err != nil || doc.Cluster.PVERelease != "9.2" {
		t.Fatalf("version recovery: %+v %v", doc.Cluster, err)
	}
}

func TestAdminHealthRegisteredButNotReady(t *testing.T) {
	config := daemonCertificates(t, t.TempDir())
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "region not ready", http.StatusServiceUnavailable)
	}))
	srv.TLS = config.Clone()
	srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, config.RootCAs
	srv.StartTLS()
	defer srv.Close()
	admin, counting := healthConsole(t, srv.URL, config)
	rec := healthRequest(t.Context(), admin, "pve-test-1", "root")
	var status resource.RegionStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || status.LastError == nil || status.LastError.Message != "not ready" ||
		counting.writes != 0 {
		t.Fatalf("readiness health: %d %s; writes=%d", rec.Code, rec.Body, counting.writes)
	}
}
