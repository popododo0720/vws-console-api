package proxmox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func powerBackend(t *testing.T, scenario pvefake.Scenario) (*Backend, *pvefake.Fake) {
	t.Helper()
	scenario.Roles = append(scenario.Roles, pvefake.Role{
		ID: "Power", Privs: []string{"VM.PowerMgmt", "VM.Allocate", "VM.Audit", "Pool.Audit"},
	})
	scenario.Tokens[0].ACL = append(scenario.Tokens[0].ACL,
		pvefake.ACE{Path: "/pool/123456789012", Role: "Power"})
	f, err := pvefake.New(scenario)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: scenario.Tokens[0].ID,
		Secret: pveclient.Secret(scenario.Tokens[0].Secret), HTTPClient: srv.Client(), PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), c, Registration{
		Region: backend.ProxmoxRegion{Name: resource.RegionName}, ClusterName: "test",
	}, RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}

func powerID(t *testing.T) resource.InstanceID {
	id, _, err := newIDs(t, "test").Instance(VM{UUID: "5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func powerCall(ctx context.Context, b *Backend, verb string, ids []resource.InstanceID,
) (resource.Accepted[resource.InstanceStateChange], error) {
	m := backend.Mutation{Scope: inventoryScope(), Key: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64)}
	switch verb {
	case "start":
		return b.StartInstances(ctx, m, resource.StartInstancesRequest{IDs: ids})
	case "stop", "shutdown":
		return b.StopInstances(ctx, m, resource.StopInstancesRequest{IDs: ids, Force: verb == "stop"})
	case "reboot":
		return b.RebootInstances(ctx, m, resource.RebootInstancesRequest{IDs: ids})
	default:
		return b.TerminateInstances(ctx, m, resource.TerminateInstancesRequest{IDs: ids})
	}
}

func powerCrossPool(t *testing.T, b *Backend, verb string) (resource.Kind, string, error) {
	id := powerID(t)
	_, err := powerCall(t.Context(), b, verb, []resource.InstanceID{id})
	return resource.KindInstance, id.String(), err
}

func TestPowerLifecycleAndRestart(t *testing.T) {
	for _, verb := range []string{"start", "shutdown", "stop", "reboot", "destroy"} {
		t.Run(verb, func(t *testing.T) {
			s := mutationScenario()
			if verb == "start" {
				s.VMs[0].Status = "stopped"
			}
			b, f := powerBackend(t, s)
			id := powerID(t)
			acc, err := powerCall(t.Context(), b, verb, []resource.InstanceID{id})
			if err != nil || len(acc.Items) != 1 || acc.Items[0].ID != id {
				t.Fatalf("accept = %+v, %v", acc, err)
			}
			decoded, err := decodeOperation(acc.Operation.ID)
			task, ok := decoded.(taskOperation)
			if err != nil || !ok || task.instance != id || task.pid == 0 {
				t.Fatalf("task coordinates = %+v, %v", decoded, err)
			}
			reopened, err := New(t.Context(), b.client, Identity(b), b.cfg)
			if err != nil {
				t.Fatal(err)
			}
			op, err := reopened.GetOperation(t.Context(), inventoryScope(), acc.Operation.ID)
			if err != nil || op.ID != acc.Operation.ID || op.State != resource.OperationSucceeded {
				t.Fatalf("poll after restart = %+v, %v", op, err)
			}
			if verb == "destroy" {
				svc := cloud.New(cloud.Config{Backends: reopened.Set(), Capabilities: reopened})
				_, err := svc.DescribeInstances(t.Context(), resource.Caller{Account: inventoryScope().Account},
					resource.InstanceQuery{IDs: []resource.InstanceID{id}})
				assertMutationNotFound(t, err, resource.KindInstance, id.String())
				requests := f.Requests()
				stop := slices.Index(requests, "POST /api2/json/nodes/pve1/qemu/100/status/stop")
				destroy := slices.IndexFunc(requests, func(r string) bool {
					return strings.HasPrefix(r, "DELETE /api2/json/nodes/pve1/qemu/100?")
				})
				if stop < 0 || destroy <= stop {
					t.Fatalf("stop before destroy: %v", requests)
				}
			} else if verb != "reboot" {
				retry, err := powerCall(t.Context(), reopened, verb, []resource.InstanceID{id})
				if err != nil || retry.Operation.ID != acc.Operation.ID {
					t.Fatalf("retry = %+v, %v; original %s", retry, err, acc.Operation.ID)
				}
			}
			doc, err := b.RegionCapabilities(t.Context(), b.region)
			if err != nil || doc.Features.TerminatedVisible || doc.Features.OperationScope != "first-task" {
				t.Fatalf("features = %+v, %v", doc.Features, err)
			}
		})
	}
}

func TestPowerRefusalsAndFailure(t *testing.T) {
	for _, mode := range []string{
		"protected", "offline", "foreign", "missing", "locked", "kept", "stopped-reboot", "failure",
	} {
		t.Run(mode, func(t *testing.T) {
			s := mutationScenario()
			if mode == "protected" {
				s.VMs[0].Config["protection"] = "1"
			}
			if mode == "foreign" {
				s.VMs[0].Pool = "999999999999"
			}
			if mode == "locked" {
				s.VMs[0].Config["lock"] = "backup"
			}
			if mode == "kept" {
				s.VMs[0].Config["scsi1"] = "local:vm-100-disk-1"
			}
			if mode == "stopped-reboot" {
				s.VMs[0].Status = "stopped"
			}
			b, f := powerBackend(t, s)
			if mode == "offline" {
				if err := f.SetNodeOnline("pve1", false); err != nil {
					t.Fatal(err)
				}
			}
			id, verb := powerID(t), "destroy"
			if mode == "missing" {
				id, _ = resource.Parse[resource.InstanceID]("i-00000000000000000")
			}
			if mode == "stopped-reboot" || mode == "failure" {
				verb = "reboot"
			}
			if mode == "failure" {
				f.FailNext("qmreboot", "injected power failure")
			}
			acc, err := powerCall(t.Context(), b, verb, []resource.InstanceID{id})
			if mode == "failure" {
				if err != nil || acc.Operation.State != resource.OperationFailed || acc.Operation.Error == nil {
					t.Fatalf("task failure = %+v, %v", acc, err)
				}
				return
			}
			want := resource.CodeConflict
			if mode == "kept" {
				want = resource.CodeInvalidArgument
			}
			if mode == "offline" {
				want = resource.CodeUnavailable
			}
			if mode == "foreign" || mode == "missing" {
				want = resource.CodeNotFound
			}
			if resource.CodeOf(err) != want {
				t.Fatalf("refusal = %v, want %v", err, want)
			}
			for _, request := range f.Requests() {
				if !strings.HasPrefix(request, "GET ") {
					t.Fatalf("refused request wrote PVE: %s", request)
				}
			}
		})
	}
}

func TestPowerQueryShapes(t *testing.T) {
	for _, action := range []string{
		"StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", "protected",
	} {
		t.Run(action, func(t *testing.T) {
			s := mutationScenario()
			if action == "StartInstances" {
				s.VMs[0].Status = "stopped"
			}
			if action == "protected" {
				s.VMs[0].Config["protection"] = "1"
			}
			b, _ := powerBackend(t, s)
			cred := sigv4.Credential{AccessKey: "AKID", Secret: "secret", Account: inventoryScope().Account}
			auth := iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)
			now := time.Now().UTC()
			h := ec2query.New(ec2query.Config{
				Service: cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b}), Authorizer: auth,
				Verifier: sigv4.NewVerifier(sigv4.Verifier{
					Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
					Now: func() time.Time { return now }, Auth: iam.Authenticator(auth),
				}),
			})
			wireAction := action
			if action == "protected" {
				wireAction = "TerminateInstances"
			}
			form := url.Values{"Action": {wireAction}, "Version": {ec2query.Version}, "InstanceId.1": {powerID(t).String()}}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://localhost/",
				strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := sigv4.Sign(r, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want, status := "<instanceId>"+powerID(t).String()+"</instanceId>", http.StatusOK
			if action == "RebootInstances" {
				want = "<return>true</return>"
			}
			if action == "protected" {
				want, status = "<Code>OperationNotPermitted</Code>", http.StatusBadRequest
			}
			if w.Code != status || !strings.Contains(w.Body.String(), want) {
				t.Fatalf("EC2 response: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
