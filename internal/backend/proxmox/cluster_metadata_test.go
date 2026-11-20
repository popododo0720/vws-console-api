package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func TestClusterMetadataFollowsQuorum(t *testing.T) {
	gate, fake, _ := testGate(t, scenario())
	b := gate.backend
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	caller := resource.Caller{Account: account}
	svc := cloud.New(cloud.Config{
		Capabilities: b, Regions: backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: b.region}}, nil),
	})
	check := func(quorum bool, state string) {
		t.Helper()
		status, err := b.Status(t.Context())
		if err != nil || status.Quorate != quorum || status.PVERelease != "9.2" || status.APINode != "pve1" {
			t.Fatalf("status: %+v %v", status, err)
		}
		doc, err := b.RegionCapabilities(t.Context(), b.region)
		if err != nil || doc.Cluster == nil || doc.Cluster.Name != "test" || doc.Cluster.APINode != "pve1" ||
			doc.Cluster.Quorate != quorum || doc.Cluster.PVERelease != "9.2" {
			t.Fatalf("capabilities: %+v %v", doc.Cluster, err)
		}
		regions, err := svc.Regions(t.Context(), caller)
		if err != nil || len(regions) != 1 || regions[0].State != state {
			t.Fatalf("regions: %+v %v", regions, err)
		}
	}
	check(true, "available")
	fake.SetQuorate(false)
	check(false, "degraded")
	fake.SetQuorate(true)
	check(true, "available")
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
	for _, reason := range []string{"", "not ready", `pool "vws-default": missing Pool.Audit`} {
		t.Run(reason, func(t *testing.T) {
			config := daemonCertificates(t, t.TempDir())
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if reason == "" {
					http.Error(w, "region not ready", http.StatusServiceUnavailable)
					return
				}
				regionapi.WriteNotReady(w, &resource.Error{Code: resource.CodeUnavailable, Message: reason})
			}))
			srv.TLS = config.Clone()
			srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, config.RootCAs
			srv.StartTLS()
			defer srv.Close()
			admin, counting := healthConsole(t, srv.URL, config)
			wantReason := reason
			if wantReason == "" {
				wantReason = "not ready"
			}
			for range 2 {
				rec := healthRequest(t.Context(), admin, "pve-test-1", "root")
				var status struct {
					resource.RegionStatus
					Status string `json:"status"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || status.Status != "degraded" ||
					status.LastError == nil || status.LastError.Message != wantReason || counting.writes != 0 {
					t.Fatalf("readiness health: %d %s; writes=%d", rec.Code, rec.Body, counting.writes)
				}
			}
		})
	}
}
