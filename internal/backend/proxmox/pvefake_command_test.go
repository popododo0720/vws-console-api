package proxmox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func TestPVEFakeCommandRegionInventoryAndRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("loopback stack requires a non-root user")
	}
	dir := t.TempDir()
	for _, target := range []struct{ name, path string }{
		{"pvefake", "./cmd/pvefake"},
		{"vws-region", "./cmd/vws-region"},
		{"helper", "./cmd/vws-region-helper"},
		{"vws-console-api", "./cmd/vws-console-api"},
	} {
		args := []string{"build", "-race", "-o", filepath.Join(dir, target.name), target.path}
		build := exec.CommandContext(t.Context(), "go", args...)
		build.Dir = "../../.."
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target.name, err, out)
		}
	}
	for _, name := range []string{
		"etc/pve/vws", "etc/pve/priv/vws", "etc/pve/priv/lock/vws-region", "etc/vws/credentials",
	} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(dir, "etc/vws/credentials/region-kek"), bytes.Repeat([]byte{42}, 32))
	writeFixture(t, filepath.Join(dir, "admin-kek"), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: true\npools:\n  project: '123456789012'\n"))
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	tlsConfig := daemonCertificates(t, dir)
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	scenarioPath := "../../../cmd/pvefake/testdata/scenario.yaml"
	scenario, err := pvefake.Load(scenarioPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(scenario.VMs) != 1 || len(scenario.Nodes) != 1 || len(scenario.Tokens) != 1 ||
		scenario.VMs[0].Pool != "123456789012" || scenario.Roles[0].ID != "PVEAuditor" {
		t.Fatalf("unexpected example: vms=%d nodes=%d tokens=%d roles=%d",
			len(scenario.VMs), len(scenario.Nodes), len(scenario.Tokens), len(scenario.Roles))
	}
	ids, err := NewIDs(scenario.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	wantID, source, err := ids.Instance(VM{UUID: option(scenario.VMs[0].Config["smbios1"], "uuid")})
	if err != nil || source != SourceUUID {
		t.Fatalf("example UUID: %v %s", err, source)
	}
	call := func(method, url, data string) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s err=%v", url, resp.StatusCode, body, err)
		}
		return body
	}
	// Decode raw JSON while vws-console-api#924 fixes typed Proxmox instance decoding in parallel.
	type inventoryPage struct {
		Items []struct {
			ID      string `json:"instanceId"`
			State   string `json:"state"`
			OwnerID string `json:"ownerId"`
		} `json:"items"`
	}
	var previous inventoryPage
	var previousInventory []byte
	for attempt := range 2 {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		t.Cleanup(cancel)
		pve := exec.CommandContext(ctx, filepath.Join(dir, "pvefake"),
			"-scenario", scenarioPath, "-listen", "127.0.0.1:0", "-ca-file", filepath.Join(dir, "pve-ca.pem"))
		var pveLog bytes.Buffer
		pve.Stderr = &pveLog
		stdout, err := pve.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := pve.Start(); err != nil {
			t.Fatal(err)
		}
		stopPVE := stopCommand(t, pve, &pveLog)
		lines := make(chan string, 2)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				lines <- scanner.Text()
			}
			close(lines)
		}()
		var endpoint string
		select {
		case endpoint = <-lines:
		case <-ctx.Done():
			t.Fatal("pvefake did not print readiness")
		}
		if !strings.HasPrefix(endpoint, "https://127.0.0.1:") {
			t.Fatalf("invalid ready URL %q", endpoint)
		}
		pem, err := os.ReadFile(filepath.Join(dir, "pve-ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("invalid pvefake CA")
		}
		pveTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
		pveClient := &http.Client{Transport: pveTransport, Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/api2/json/cluster/resources?type=vm", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "PVEAPIToken="+scenario.Tokens[0].ID+"="+scenario.Tokens[0].Secret)
		resp, err := pveClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		inventory, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		pveTransport.CloseIdleConnections()
		if err != nil || resp.StatusCode != http.StatusOK || !bytes.Contains(inventory, []byte(`"vmid":100`)) {
			t.Fatalf("PVE inventory: %s %v", inventory, err)
		}
		if attempt > 0 && !bytes.Equal(inventory, previousInventory) {
			t.Fatalf("PVE restart changed inventory: %s != %s", inventory, previousInventory)
		}
		previousInventory = inventory
		addr, ops := unusedAddress(t), unusedAddress(t)
		region := exec.CommandContext(ctx, filepath.Join(dir, "vws-region"),
			"-backend", "proxmox", "-config", filepath.Join(dir, "region.yaml"),
			"-registration-file", filepath.Join(dir, "etc/pve/vws", "registration.json"),
			"-helper-path", filepath.Join(dir, "helper"), "-helper-root", dir, "-pve-endpoint", endpoint,
			"-pve-ca-file", filepath.Join(dir, "pve-ca.pem"),
			"-tls-cert-file", filepath.Join(dir, "cert.pem"), "-tls-key-file", filepath.Join(dir, "key.pem"),
			"-tls-ca-file", filepath.Join(dir, "ca.pem"), "-region-addr", addr, "-ops-addr", ops)
		var regionLog bytes.Buffer
		region.Stdout, region.Stderr = &regionLog, &regionLog
		region.Env = append(os.Environ(), "OTEL_EXPORTER_OTLP_ENDPOINT=")
		if err := region.Start(); err != nil {
			t.Fatal(err)
		}
		stopRegion := stopCommand(t, region, &regionLog)
		consoleAddr, consoleOps := unusedAddress(t), unusedAddress(t)
		global := exec.CommandContext(ctx, filepath.Join(dir, "vws-console-api"),
			"-backend", "regions", "-admin-store", "memory", "-admin-kek-file", filepath.Join(dir, "admin-kek"),
			"-region-mtls-ca-file", filepath.Join(dir, "ca.pem"),
			"-region-mtls-cert-file", filepath.Join(dir, "cert.pem"), "-region-mtls-key-file", filepath.Join(dir, "key.pem"),
			"-console-token", "loopback-token", "-access-key", "loopback-key", "-secret", "loopback-secret",
			"-console-addr", consoleAddr, "-ops-addr", consoleOps,
			"-ec2-addr", unusedAddress(t), "-s3-addr", unusedAddress(t), "-iam-addr", unusedAddress(t))
		var globalLog bytes.Buffer
		global.Stdout, global.Stderr = &globalLog, &globalLog
		global.Env = append(os.Environ(), "OTEL_EXPORTER_OTLP_ENDPOINT=")
		if err := global.Start(); err != nil {
			t.Fatal(err)
		}
		stopGlobal := stopCommand(t, global, &globalLog)
		awaitStatus(t, "http://"+consoleOps+"/readyz", http.StatusOK)
		var etag string
		admin := func(method, path, body string, want int) []byte {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, method, "http://"+consoleAddr+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer loopback-token")
			req.Header.Set("Content-Type", "application/json")
			if method == http.MethodPatch || method == http.MethodDelete {
				req.Header.Set("If-Match", etag)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if value := resp.Header.Get("ETag"); value != "" {
				etag = value
			}
			data, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != want || bytes.Contains(data, []byte("fake-secret")) {
				t.Fatalf("%s %s: status=%d body=%s err=%v", method, path, resp.StatusCode, data, err)
			}
			return data
		}
		const regionsPath = "/api/v1/admin/regions"
		const regionPath = regionsPath + "/pve-test-1"
		if data := admin(http.MethodGet, regionsPath, "", http.StatusOK); strings.TrimSpace(string(data)) != `{"items":[]}` {
			t.Fatalf("new memory registry retained registrations: %s", data)
		}
		if attempt == 0 {
			awaitStatus(t, "http://"+ops+"/readyz", http.StatusServiceUnavailable)
			awaitClientStatus(t, client, "https://"+addr+"/internal/v1/status", http.StatusServiceUnavailable)
		}
		input := fmt.Sprintf(`{"name":"pve-test-1","clusterName":"test","pveApiUrl":%q,"caPem":%q,
			"tokenId":"vws@pve!inventory","tokenSecret":"fake-secret","regionEndpoint":%q,
			"zones":[{"letter":"a","nodes":["pve1"]}]}`, endpoint, pem, "https://"+addr)
		data := admin(http.MethodPost, regionsPath, input, http.StatusCreated)
		if bytes.Contains(data, []byte(`"lastError":{`)) {
			t.Fatalf("registration push failed: %s", data)
		}
		awaitStatus(t, "http://"+ops+"/readyz", http.StatusOK)
		data = admin(http.MethodPost, regionPath+"/test", `{"tokenSecret":"fake-secret"}`, http.StatusOK)
		var diagnostic struct {
			Steps []struct {
				Result string `json:"result"`
			} `json:"steps"`
		}
		if err := json.Unmarshal(data, &diagnostic); err != nil || len(diagnostic.Steps) != 5 {
			t.Fatalf("connection diagnostic: %s %v", data, err)
		}
		for _, step := range diagnostic.Steps {
			if step.Result != "PASS" {
				t.Fatalf("connection test failed: %s", data)
			}
		}
		for range 2 {
			data := admin(http.MethodGet, regionPath+"/health", "", http.StatusOK)
			if !bytes.Contains(data, []byte(`"quorate":true`)) || !bytes.Contains(data, []byte(`"name":"pve1"`)) {
				t.Fatalf("region health: %s", data)
			}
			data = admin(http.MethodPatch, regionPath, `{"zones":[{"letter":"b","nodes":["pve1"]}]}`, http.StatusOK)
			if !bytes.Contains(data, []byte(`"letter":"b"`)) || bytes.Contains(data, []byte(`"lastError":{`)) {
				t.Fatalf("zone update: %s", data)
			}
			identity, err := os.ReadFile(filepath.Join(dir, "etc/pve/vws/registration.json"))
			if err != nil || !bytes.Contains(identity, []byte(`"letter":"b"`)) {
				t.Fatalf("daemon did not persist zones: %s %v", identity, err)
			}
		}
		for range 2 {
			body := call(http.MethodPost, "https://"+addr+"/internal/v1/Compute/DescribeInstances",
				`{"scope":{"account":"123456789012","pool":"123456789012"},"req":{}}`)
			var page inventoryPage
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 || page.Items[0].ID != wantID.String() ||
				page.Items[0].State != "running" || page.Items[0].OwnerID != "123456789012" {
				t.Fatalf("scenario instance missing from region: %s", body)
			}
			if attempt > 0 && !reflect.DeepEqual(page, previous) {
				t.Fatalf("region restart changed inventory: got=%+v want=%+v", page, previous)
			}
			previous = page
		}
		admin(http.MethodDelete, regionPath, "", http.StatusNoContent)
		if data := admin(http.MethodGet, regionsPath, "", http.StatusOK); strings.TrimSpace(string(data)) != `{"items":[]}` {
			t.Fatalf("deleted region retained: %s", data)
		}
		stopGlobal()
		stopRegion()
		stopPVE()
		cancel()
		if strings.Contains(regionLog.String()+globalLog.String(), "fake-secret") {
			t.Fatal("token in process logs")
		}
		if line, ok := <-lines; ok {
			t.Fatalf("printed more than one ready line: %q", line)
		}
	}
}

func stopCommand(t *testing.T, cmd *exec.Cmd, output *bytes.Buffer) func() {
	t.Helper()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("process: %v\n%s", err, output.String())
		}
	}
	t.Cleanup(stop)
	return stop
}
