package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore/etcdtest"
	"github.com/popododo0720/vws-console-api/internal/proxy"
)

func TestLiveRegistryProjectRemapAndRestart(t *testing.T) {
	iam := etcdtest.Start(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "global.yaml")
	data := fmt.Sprintf("iam:\n  etcd_endpoints: [%s]\n  tls: {ca_file: %s}\n"+
		"credentials: {kek_file: %s}\ndefault_project: default\n",
		iam.EtcdEndpoints[0], iam.TLS.CAFile, filepath.Join(dir, "unused-kek"))
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	admin, closeAdmin, err := openRegistry(t.Context(), path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Error(err)
		}
	})
	for _, id := range []string{"123456789012", "987654321098"} {
		if _, err := admin.AWSAccounts().Create(t.Context(), store.AWSAccount{
			ID: id, RoleARN: "arn:aws:iam::" + id + ":role/inventory", AllowedRegions: []string{"us-east-1"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "aws-external-id-"+id), []byte("credential-"+id), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		registry, closeRegistry, err := openRegistry(t.Context(), path, "", "")
		if err != nil {
			t.Fatal(err)
		}
		accounts := proxy.RegistryAccounts{Registry: registry, CredentialDirectory: dir}
		var revision int64
		for _, id := range []string{"123456789012", "987654321098"} {
			mapping, err := admin.Projects().Get(t.Context(), "111111111111")
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Fatal(err)
			}
			mapping.Project, mapping.AWSAccounts = "111111111111", []string{id}
			if _, err := admin.Projects().Put(t.Context(), mapping); err != nil {
				t.Fatal(err)
			}
			a, err := accounts.Account(t.Context(), "111111111111", "us-east-1")
			if err != nil || a.ID != id || a.RoleARN != "arn:aws:iam::"+id+":role/inventory" ||
				a.ExternalID != "credential-"+id || a.MappingVersion <= revision {
				t.Fatalf("live mapping not observed: account=%s revision=%d error=%v", a.ID, a.MappingVersion, err)
			}
			revision = a.MappingVersion
		}
		if err := closeRegistry(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRegistryBootstrapAndSnapshots(t *testing.T) {
	dir := t.TempDir()
	accounts, projects := filepath.Join(dir, "accounts.json"), filepath.Join(dir, "projects.json")
	for path, content := range map[string]string{
		accounts: `[{"awsAccountId":"123456789012","roleArn":"arn:aws:iam::123456789012:role/inventory",` +
			`"allowedRegions":["us-east-1"]}]`,
		projects: `[{"project":"111111111111","awsAccounts":["123456789012"]}]`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	registry, closeRegistry, err := openRegistry(t.Context(), "", accounts, projects)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeRegistry(); err != nil {
		t.Fatal(err)
	}
	mapping, err := registry.Projects().Get(t.Context(), "111111111111")
	if err != nil || len(mapping.AWSAccounts) != 1 || mapping.AWSAccounts[0] != "123456789012" {
		t.Fatal("snapshot did not load the project mapping")
	}
	for _, paths := range [][3]string{
		{accounts, accounts, projects},
		{accounts, "", ""},
		{filepath.Join(dir, "missing"), "", ""},
		{"", "", projects},
		{"", accounts, ""},
		{"", projects, accounts},
	} {
		if _, _, err := openRegistry(t.Context(), paths[0], paths[1], paths[2]); err == nil {
			t.Fatal("invalid or conflicting registry inputs accepted")
		}
	}
}

func TestBootstrapErrorsHideCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.yaml")
	data := "iam:\n  etcd_endpoints: [https://127.0.0.1:2379]\n  tls: {ca_file: /unused/ca}\n" +
		"credentials: {kek_file: /unused/kek}\ndefault_project: secret-canary/value\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := openRegistry(t.Context(), path, "", "")
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("bootstrap error disclosed an invalid field value")
	}
}
