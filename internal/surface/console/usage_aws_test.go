package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/awssdk"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/proxy"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestUsageAWSCostThroughProxyReadOnly(t *testing.T) {
	e, registry := adminFixture(t)
	h := e.h.(*handler)
	h.svc = cloud.New(cloud.Config{Backends: backend.Set{Usage: allocationReader(func(
		context.Context, backend.Scope, struct{},
	) (resource.Allocation, error) {
		return resource.Allocation{VCPU: 2}, nil
	})}})
	bearer := map[string]string{"Authorization": "Bearer tok"}
	rec := e.do(t, "GET", usagePath, "", bearer)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"aws":[]`) {
		t.Fatalf("unmapped AWS: %d %s", rec.Code, rec.Body)
	}
	dir, err := os.MkdirTemp("", "u")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	first, err := registry.AWSAccounts().Get(t.Context(), e.account.String())
	if err != nil {
		t.Fatal(err)
	}
	first.RoleARN, first.AllowedRegions = "arn:aws:iam::"+first.ID+":role/usage", []string{"eu-west-1"}
	first, err = registry.AWSAccounts().Update(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/usage", AllowedRegions: []string{"eu-west-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ID, second.ID} {
		if err := os.WriteFile(filepath.Join(dir, "aws-external-id-"+id), []byte("external-canary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mapping, err := registry.Projects().Put(t.Context(), store.Project{
		Project: e.account.String(), Pools: []store.ProjectPool{{Region: "pve-lab-1", Pool: e.account.String()}},
		AWSAccounts: []string{second.ID, first.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var reads, assumes atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assumes.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		token := "success"
		if strings.Contains(r.Form.Get("RoleArn"), second.ID) {
			token = "failure"
		}
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>`+
			`<AccessKeyId>session-key</AccessKeyId><SecretAccessKey>session-secret</SecretAccessKey>`+
			`<SessionToken>%s</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>`+
			`</Credentials></AssumeRoleResult></AssumeRoleResponse>`, token)
	}))
	defer sts.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "AWSInsightsIndexService.GetCostAndUsage" ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/ce/aws4_request") ||
			r.Header.Get("X-Vws-Aws-Account") != "" || r.Header.Get("X-Vws-Account") != "" {
			t.Error("CE did not traverse signing proxy")
		}
		var request struct {
			TimePeriod struct{ Start, End string }
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.TimePeriod.Start != "2026-10-01" || request.TimePeriod.End != "2026-11-01" {
			t.Error("CE received wrong usage window")
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if r.Header.Get("X-Amz-Security-Token") == "failure" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"__type":"AccessDeniedException","Message":"credential-canary"}`)
			return
		}
		fmt.Fprint(w, `{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"0.10","Unit":"USD"}}},`+
			`{"Total":{"UnblendedCost":{"Amount":"0.20","Unit":"USD"}}}]}`)
	}))
	defer origin.Close()
	want := ""
	for range 2 {
		p, err := proxy.New(proxy.RegistryAccounts{Registry: registry, CredentialDirectory: dir},
			sigv4.Credential{AccessKey: "source-key", Secret: "source-secret"}, sts.URL, "us-east-1", origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.ServiceEndpoint(origin.URL); err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "s")
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: p, ReadHeaderTimeout: time.Second}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		client, err := awssdk.NewConnectionClient(socket)
		if err != nil {
			t.Fatal(err)
		}
		h.awsCost = client.Cost
		for range 2 {
			rec = e.do(t, "GET", usagePath, "", bearer)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"allocation":{"vcpu":2,`) ||
				!strings.Contains(rec.Body.String(), `"aws":[{"account":"123456789012","amount":"0.30","unit":"USD"},`+
					`{"account":"222222222222","error":"Unavailable"}]`) {
				t.Fatalf("AWS usage: %d %s", rec.Code, rec.Body)
			}
			if want != "" && rec.Body.String() != want {
				t.Fatal("identical inputs changed response across retry or restart")
			}
			want = rec.Body.String()
		}
		client.Close()
		server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	}
	after, err := registry.Projects().Get(t.Context(), mapping.Project)
	if err != nil || !reflect.DeepEqual(mapping, after) {
		t.Fatalf("usage wrote project: %+v, %v", after, err)
	}
	for _, before := range []store.AWSAccount{first, second} {
		after, err := registry.AWSAccounts().Get(t.Context(), before.ID)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("usage wrote account: %+v, %v", after, err)
		}
	}
	if reads.Load() != 8 || assumes.Load() != 4 {
		t.Fatalf("unexpected cost reads=%d, STS=%d", reads.Load(), assumes.Load())
	}
}
