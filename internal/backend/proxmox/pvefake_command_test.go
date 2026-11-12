package proxmox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	dir := t.TempDir()
	for _, target := range []struct{ name, path string }{
		{"pvefake", "./cmd/pvefake"},
		{"vws-region", "./cmd/vws-region"},
		{"helper", "./internal/regionhelper"},
	} {
		args := []string{"build", "-race", "-o", filepath.Join(dir, target.name), target.path}
		if target.name == "helper" {
			args = []string{"test", "-c", "-o", filepath.Join(dir, target.name), target.path}
		}
		build := exec.CommandContext(t.Context(), "go", args...)
		build.Dir = "../../.."
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target.name, err, out)
		}
	}
	for _, name := range []string{"public", "private", "locks"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(dir, "region-kek"), bytes.Repeat([]byte{42}, 32))
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: true\n"))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("VWS_HELPER_TEST_ROOT", dir)
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
		t.Fatalf("unexpected example: %+v", scenario)
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
			"-registration-file", filepath.Join(dir, "public", "registration.json"),
			"-helper-path", filepath.Join(dir, "helper"), "-pve-endpoint", endpoint,
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
		if attempt == 0 {
			awaitStatus(t, "http://"+ops+"/readyz", http.StatusServiceUnavailable)
			awaitClientStatus(t, client, "https://"+addr+"/internal/v1/status", http.StatusServiceUnavailable)
			for range 2 {
				call(http.MethodPut, "https://"+addr+"/internal/v1/registration",
					`{"region":"pve-test-1","cluster_name":"test","tokenId":"vws@pve!inventory",`+
						`"token":"fake-secret","zones":[{"letter":"a","nodes":["pve1"]}]}`)
			}
		}
		awaitStatus(t, "http://"+ops+"/readyz", http.StatusOK)
		for range 2 {
			body := call(http.MethodPost, "https://"+addr+"/internal/v1/Compute/DescribeInstances",
				`{"scope":{"account":"123456789012"},"req":{}}`)
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
		stopRegion()
		stopPVE()
		cancel()
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
