package proxy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

type unavailableAccounts struct{}

func (unavailableAccounts) Account(context.Context, string, string) (Account, error) {
	return Account{}, errors.New("registry temporarily unavailable")
}

func (f *fixture) mapProject(t *testing.T, project string, accounts ...string) {
	t.Helper()
	mapping, err := f.registry.Projects().Get(t.Context(), project)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	mapping.Project, mapping.AWSAccounts = project, accounts
	if _, err := f.registry.Projects().Put(t.Context(), mapping); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) addAWSAccount(t *testing.T, regions ...string) {
	t.Helper()
	if _, err := f.registry.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "987654321098", RoleARN: "arn:aws:iam::987654321098:role/second", AllowedRegions: regions,
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "aws-external-id-987654321098")
	if err := os.WriteFile(path, []byte("second-external"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProjectRolesAndRegionalSelection(t *testing.T) {
	f := setup(t)
	f.addAWSAccount(t, "us-east-1")
	f.mapProject(t, "111111111111", "123456789012")
	f.mapProject(t, "222222222222", "987654321098")
	for range 2 {
		for _, project := range []string{"111111111111", "222222222222"} {
			if w := f.requestProject("Action=DescribeInstances", "principal", "us-east-1", project); w.Code != 200 {
				t.Fatalf("project %s: %d %s", project, w.Code, w.Body)
			}
		}
	}
	if f.stsCalls != 2 || f.originCalls != 4 {
		t.Fatalf("STS=%d origin=%d", f.stsCalls, f.originCalls)
	}
	for i, want := range []struct{ project, role, external string }{
		{"111111111111", "arn:aws:iam::123456789012:role/inventory", "external-canary"},
		{"222222222222", "arn:aws:iam::987654321098:role/second", "second-external"},
	} {
		got := f.stsForms[i]
		if got.Get("RoleArn") != want.role || got.Get("ExternalId") != want.external ||
			!strings.HasPrefix(got.Get("RoleSessionName"), "vws-"+want.project+"-") {
			t.Fatalf("project %s did not use its own role, external ID and session name", want.project)
		}
	}
	second, err := f.registry.AWSAccounts().Get(t.Context(), "987654321098")
	if err != nil {
		t.Fatal(err)
	}
	second.AllowedRegions = []string{"eu-west-1"}
	if _, err := f.registry.AWSAccounts().Update(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	// The order of the account IDs must not select an account for another region.
	f.mapProject(t, "111111111111", "987654321098", "123456789012")
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == f.stsHost {
				return http.DefaultTransport.RoundTrip(r)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
		})
		if w := f.requestProject("Action=DescribeInstances", "principal", region, "111111111111"); w.Code != 200 {
			t.Fatalf("region %s: %d %s", region, w.Code, w.Body)
		}
	}
	if f.stsCalls != 4 ||
		f.stsForms[2].Get("RoleArn") != "arn:aws:iam::123456789012:role/inventory" ||
		f.stsForms[3].Get("RoleArn") != "arn:aws:iam::987654321098:role/second" {
		t.Fatal("regional mapping selected the wrong role")
	}
}

func TestProjectMappingDenialsMakeNoSTSCall(t *testing.T) {
	for _, scenario := range []string{"absent", "empty", "ambiguous", "missing-account", "wrong-role-account", "region"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			project, region := "111111111111", "us-east-1"
			switch scenario {
			case "absent":
			case "empty":
				f.mapProject(t, project)
			case "ambiguous":
				f.addAWSAccount(t, region)
				f.mapProject(t, project, "123456789012", "987654321098")
			case "missing-account":
				f.mapProject(t, project, "000000000000", "123456789012")
			case "wrong-role-account":
				a, err := f.registry.AWSAccounts().Get(t.Context(), "123456789012")
				if err != nil {
					t.Fatal(err)
				}
				a.RoleARN = "arn:aws:iam::000000000000:role/foreign"
				if _, err := f.registry.AWSAccounts().Update(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				f.mapProject(t, project, a.ID)
			case "region":
				f.mapProject(t, project, "123456789012")
				region = "eu-west-1"
			default:
				t.Fatal("unknown scenario")
			}
			w := f.requestProject("Action=DescribeInstances", "principal", region, project)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") ||
				f.stsCalls != 0 || f.originCalls != 0 {
				t.Fatalf("denial made an outbound call: %d %s; STS=%d origin=%d", w.Code, w.Body, f.stsCalls, f.originCalls)
			}
		})
	}
}

func TestProjectRemapDropsSessionsAndSurvivesRestart(t *testing.T) {
	f := setup(t)
	f.addAWSAccount(t, "us-east-1")
	for _, account := range []string{"123456789012", "987654321098", "123456789012"} {
		for range 2 {
			f.mapProject(t, "123456789012", account)
			if w := f.request("Action=DescribeInstances"); w.Code != 200 {
				t.Fatalf("remap: %d %s", w.Code, w.Body)
			}
			if len(f.p.cache) != 1 {
				t.Fatal("old mapping credentials retained")
			}
		}
	}
	roles := make([]string, 0, len(f.stsForms))
	for _, form := range f.stsForms {
		roles = append(roles, form.Get("RoleArn"))
	}
	if !slices.Equal(roles, []string{
		"arn:aws:iam::123456789012:role/inventory", "arn:aws:iam::987654321098:role/second",
		"arn:aws:iam::123456789012:role/inventory",
	}) {
		t.Fatal("remap reused a previous mapping's session")
	}
	f.mapProject(t, "123456789012")
	if w := f.request("Action=DescribeInstances"); w.Code != 403 || len(f.p.cache) != 0 || f.stsCalls != 3 {
		t.Fatal("unmapping retained credentials or called STS")
	}
	f.mapProject(t, "123456789012", "123456789012")
	old := f.p
	var err error
	f.p, err = New(old.accounts, old.source, old.sts, old.stsRegion, old.origin)
	if err != nil {
		t.Fatal(err)
	}
	if transport, ok := f.p.transport.(*http.Transport); ok {
		t.Cleanup(transport.CloseIdleConnections)
	}
	if w := f.request("Action=DescribeInstances"); w.Code != 200 || f.stsCalls != 4 {
		t.Fatal("restart did not resolve the current project mapping")
	}
}

func TestProjectRoleAndExternalIDRotation(t *testing.T) {
	f := setup(t)
	if w := f.request("Action=DescribeInstances"); w.Code != 200 {
		t.Fatal(w.Body)
	}
	a, err := f.registry.AWSAccounts().Get(t.Context(), "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	a.RoleARN = "arn:aws:iam::123456789012:role/rotated"
	if _, err := f.registry.AWSAccounts().Update(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if w := f.request("Action=DescribeInstances"); w.Code != 200 || f.stsCalls != 2 ||
		f.stsForms[1].Get("RoleArn") != a.RoleARN {
		t.Fatal("changed role reused credentials")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "aws-external-id-"+a.ID), []byte("rotated-external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := f.request("Action=DescribeInstances"); w.Code != 200 || f.stsCalls != 3 ||
		f.stsForms[2].Get("ExternalId") != "rotated-external" {
		t.Fatal("changed external ID reused credentials")
	}
}

func TestUnreadableMappingKeepsCacheButStillDenies(t *testing.T) {
	f := setup(t)
	if w := f.request("Action=DescribeInstances"); w.Code != 200 {
		t.Fatal(w.Body)
	}
	accounts := f.p.accounts
	f.p.accounts = unavailableAccounts{}
	w := f.request("Action=DescribeInstances")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") ||
		len(f.p.cache) != 1 || f.stsCalls != 1 || f.originCalls != 1 {
		t.Fatal("unreadable mapping purged the cache or allowed forwarding")
	}
	f.p.accounts = accounts
	if w := f.request("Action=DescribeInstances"); w.Code != 200 || f.stsCalls != 1 {
		t.Fatal("registry recovery did not retain the valid session")
	}
	f.p.accounts = RegistryAccounts{Registry: store.New(store.NewMemory()), CredentialDirectory: f.dir}
	if w := f.request("Action=DescribeInstances"); w.Code != 403 || len(f.p.cache) != 0 || f.stsCalls != 1 {
		t.Fatal("a known absent mapping did not discard the session")
	}
	f.p.accounts = accounts
	if w := f.request("Action=DescribeInstances"); w.Code != 200 || f.stsCalls != 2 {
		t.Fatal("a session survived the known absent mapping")
	}
	f.mapProject(t, "123456789012", "000000000000")
	if w := f.request("Action=DescribeInstances"); w.Code != 403 || len(f.p.cache) != 0 || f.stsCalls != 2 {
		t.Fatal("a known remap to an unreadable account did not discard the session")
	}
}
