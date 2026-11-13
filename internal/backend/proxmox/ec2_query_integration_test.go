package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type queryRegionCapabilities struct{ client *regionapi.Client }

func (c queryRegionCapabilities) RegionCapabilities(
	ctx context.Context, _ string,
) (resource.RegionCapabilities, error) {
	return c.client.Capabilities(ctx)
}

func TestEC2QueryProxmoxRegionalLifecycle(t *testing.T) {
	b, _ := volumeWorld(t, nil)
	var absentCalls atomic.Int32
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", CheckScope: ScopeCheck(b),
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := daemonCertificates(t, t.TempDir())
	var handlerMu sync.RWMutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerMu.RLock()
		defer handlerMu.RUnlock()
		switch r.URL.Path {
		case "/internal/v1/Network/AllocateAddress", "/internal/v1/Network/CreateVpc",
			"/internal/v1/Network/DescribeAddresses":
			absentCalls.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	srv.TLS = config.Clone()
	srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, config.RootCAs
	srv.StartTLS()
	defer srv.Close()
	client, err := regionapi.NewClient(srv.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	registry := store.New(store.NewMemory())
	if _, err := registry.Regions().Create(t.Context(), store.Region{
		Name: "pve-test-1", RegionEndpoint: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "tenant_pool"}},
	}); err != nil {
		t.Fatal(err)
	}
	routed, err := regionset.New(registry.Catalog(), func(
		context.Context, backend.ProxmoxRegion,
	) (regionclient.Transport, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	newQuery := func() http.Handler {
		svc := cloud.New(cloud.Config{
			Backends: routed, Regions: registry.Catalog(), Region: "pve-test-1",
			Capabilities: queryRegionCapabilities{client: client},
		})
		auth := iam.NewStatic("AKIDEXAMPLE", "secret", inventoryScope().Account)
		return ec2query.New(ec2query.Config{
			Service: svc, Authorizer: auth, Verifier: sigv4.NewVerifier(sigv4.Verifier{
				Service: sigv4.ServiceEC2, Regions: registry.Catalog(), Auth: iam.Authenticator(auth),
			}),
		})
	}
	query := newQuery()
	// Send aws-cli's EC2 Query POST forms from Go; no aws binary is required.
	send := func(action string, fields url.Values, status int) string {
		t.Helper()
		form := url.Values{"Action": {action}, "Version": {"2016-11-15"}}
		for key, values := range fields {
			form[key] = values
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://localhost/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		if err := sigv4.Sign(req, sigv4.Credential{
			AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: inventoryScope().Account,
		}, sigv4.ServiceEC2, "pve-test-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		res := httptest.NewRecorder()
		query.ServeHTTP(res, req)
		if res.Code != status {
			t.Fatalf("%s: HTTP %d, want %d: %s", action, res.Code, status, res.Body)
		}
		t.Logf("%s: HTTP %d", action, res.Code)
		return res.Body.String()
	}
	id := powerID(t).String()
	instance := url.Values{"InstanceId.1": {id}}
	describe := func(state string) {
		t.Helper()
		body := send("DescribeInstances", instance, http.StatusOK)
		if queryXML(t, body, "instanceId") != id || !strings.Contains(body, "<name>"+state+"</name>") {
			t.Fatalf("instance must be %s: %s", state, body)
		}
	}
	// RunInstances cannot finalize on main until #772 / PR #983 lands.
	describe("running")
	send("StopInstances", instance, http.StatusOK)
	describe("stopped")
	send("StartInstances", instance, http.StatusOK)
	describe("running")
	if body := send("RebootInstances", instance, http.StatusOK); queryXML(t, body, "return") != "true" {
		t.Fatalf("reboot response: %s", body)
	}
	describe("running")
	send("StopInstances", instance, http.StatusOK)
	describe("stopped")
	create := url.Values{
		"AvailabilityZone": {"pve-test-1a"}, "Size": {"1"}, "VolumeType": {"gp2"}, "ClientToken": {"query-volume"},
	}
	volume := queryXML(t, send("CreateVolume", create, http.StatusOK), "volumeId")
	// Recreate both kernels/backends over the same PVE state before replaying.
	fresh := reopenedAttachments(t, b)
	restarted, err := regionapi.New(regionapi.Config{
		Backend: fresh.Set(), Capabilities: fresh, Region: "pve-test-1", CheckScope: ScopeCheck(fresh),
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handlerMu.Lock()
	h = restarted
	handlerMu.Unlock()
	query = newQuery()
	if body := send("CreateVolume", create, http.StatusOK); queryXML(t, body, "volumeId") != volume {
		t.Fatalf("restart replay changed volume %s: %s", volume, body)
	}
	attachment := url.Values{"VolumeId": {volume}, "InstanceId": {id}, "Device": {"/dev/sdf"}}
	if body := send("AttachVolume", attachment, http.StatusOK); queryXML(t, body, "instanceId") != id {
		t.Fatalf("attachment instance: %s", body)
	}
	body := send("DescribeVolumes", url.Values{"VolumeId.1": {volume}}, http.StatusOK)
	if queryXML(t, body, "status") != "in-use" {
		t.Fatalf("attached volume: %s", body)
	}
	send("DetachVolume", attachment, http.StatusOK)
	body = send("DescribeVolumes", url.Values{"VolumeId.1": {volume}}, http.StatusOK)
	if queryXML(t, body, "status") != "available" {
		t.Fatalf("detached volume: %s", body)
	}
	send("DeleteVolume", url.Values{"VolumeId": {volume}}, http.StatusOK)
	if body := send("DescribeVolumes", nil, http.StatusOK); strings.Contains(body, "<volumeId>"+volume+"</volumeId>") {
		t.Fatalf("deleted volume remains visible: %s", body)
	}
	send("TerminateInstances", instance, http.StatusOK)
	if body := send("DescribeInstances", nil, http.StatusOK); strings.Contains(body, "<instanceId>"+id+"</instanceId>") {
		t.Fatalf("terminated instance remains visible: %s", body)
	}
	// AWS error-code contract: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
	for action, fields := range map[string]url.Values{
		"AllocateAddress": {"Domain": {"vpc"}},
		"CreateVpc":       {"CidrBlock": {"10.0.0.0/16"}},
	} {
		if body := send(action, fields, http.StatusBadRequest); queryXML(t, body, "Code") != "UnsupportedOperation" {
			t.Fatalf("%s must be unsupported: %s", action, body)
		}
	}
	body = send("DescribeAddresses", nil, http.StatusOK)
	var addresses struct {
		Set *struct {
			Items []struct{} `xml:"item"`
		} `xml:"addressesSet"`
	}
	err = xml.Unmarshal([]byte(body), &addresses)
	if err != nil || addresses.Set == nil || len(addresses.Set.Items) != 0 {
		t.Fatalf("addresses must be an empty set: %s (%v)", body, err)
	}
	if absentCalls.Load() != 0 {
		t.Fatalf("unsupported mutations or empty reads reached regional backends: %d", absentCalls.Load())
	}
	for action, fields := range map[string]url.Values{
		"StopInstances": {"InstanceId.1": {"i-../../etc/passwd"}},
		"DropTables":    nil,
	} {
		want := "InvalidAction"
		if action == "StopInstances" {
			want = "InvalidInstanceID.Malformed"
		}
		if body := send(action, fields, http.StatusBadRequest); queryXML(t, body, "Code") != want {
			t.Fatalf("%s must return %s: %s", action, want, body)
		}
	}
	sdn, _ := sdnBackend(t, sdnScenario())
	sdnHandler, err := regionapi.New(regionapi.Config{
		Backend: sdn.Set(), Capabilities: sdn, Region: "pve-test-1", CheckScope: ScopeCheck(sdn),
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handlerMu.Lock()
	h = sdnHandler
	handlerMu.Unlock()
	vpc := queryXML(t, send("CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}}, http.StatusOK), "vpcId")
	if body := send("DescribeVpcs", url.Values{"VpcId.1": {vpc}}, http.StatusOK); queryXML(t, body, "vpcId") != vpc {
		t.Fatalf("SDN read after write: %s", body)
	}
	send("DescribeSubnets", nil, http.StatusOK)
	body = send("CreateSubnet", url.Values{"VpcId": {vpc}, "CidrBlock": {"10.0.1.0/24"}}, http.StatusBadRequest)
	if queryXML(t, body, "Code") != "UnsupportedOperation" {
		t.Fatalf("part 1 must keep subnet writes unsupported: %s", body)
	}
	send("DeleteVpc", url.Values{"VpcId": {vpc}}, http.StatusOK)
	body = send("DeleteVpc", url.Values{"VpcId": {vpc}}, http.StatusBadRequest)
	if queryXML(t, body, "Code") != "InvalidVpcID.NotFound" {
		t.Fatalf("SDN missing delete: %s", body)
	}
}

func queryXML(t *testing.T, body, tag string) string {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			t.Fatalf("missing XML element %s: %s (%v)", tag, body, err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == tag {
			var text string
			if err := decoder.DecodeElement(&text, &start); err != nil {
				t.Fatal(err)
			}
			return text
		}
	}
}
