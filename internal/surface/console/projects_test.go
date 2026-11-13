package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

const projectsPath = "/api/v1/projects"

func listProjectsCall(t *testing.T, e loginEnv, want int) ([]projectView, string) {
	t.Helper()
	rec := e.do(t, http.MethodGet, projectsPath, "", map[string]string{"Authorization": "Bearer tok"})
	if rec.Code != want {
		t.Fatalf("GET %s: %d %s, want %d", projectsPath, rec.Code, rec.Body, want)
	}
	var body struct {
		Items []projectView `json:"items"`
	}
	if want == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
	}
	return body.Items, rec.Body.String()
}

func TestListProjectsMappedAndDefault(t *testing.T) {
	e, g := adminFixture(t)
	if _, err := g.Regions().Create(t.Context(), store.Region{
		Name: "pve-other-1", ClusterName: "other", PVEAPIURL: "https://10.20.30.40:8006",
		TokenID: "vws@pve!canary-token-id", TokenSecret: store.DescribeSecret("pve-other-secret"),
	}); err != nil {
		t.Fatal(err)
	}

	items, _ := listProjectsCall(t, e, http.StatusOK)
	want := []projectRegion{
		{Name: "pve-lab-1", Kind: "pve", Pool: "123456789012"},
		{Name: "pve-other-1", Kind: "pve", Pool: "123456789012"},
	}
	if len(items) != 1 || items[0].Project != "123456789012" || !slices.Equal(items[0].Regions, want) {
		t.Fatalf("unmapped project: %+v", items)
	}
	if _, err := g.Projects().Get(t.Context(), "123456789012"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("listing persisted a default mapping: %v", err)
	}

	for _, account := range []store.AWSAccount{
		{
			ID: "210987654321", RoleARN: "arn:aws:iam::210987654321:role/canary-role-one",
			ExternalID: store.DescribeSecret("canary-external-one"), AllowedRegions: []string{"us-east-1", "eu-west-1"},
		},
		{
			ID: "345678901234", RoleARN: "arn:aws:iam::345678901234:role/canary-role-two",
			ExternalID: store.DescribeSecret("canary-external-two"), AllowedRegions: []string{"us-east-1", "ap-northeast-2"},
		},
	} {
		if _, err := g.AWSAccounts().Create(t.Context(), account); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Projects().Put(t.Context(), store.Project{
		Project:     "123456789012",
		Pools:       []store.ProjectPool{{Region: "pve-other-1", Pool: "team-a"}},
		AWSAccounts: []string{"345678901234", "210987654321"},
	}); err != nil {
		t.Fatal(err)
	}

	items, body := listProjectsCall(t, e, http.StatusOK)
	want = []projectRegion{
		{Name: "pve-other-1", Kind: "pve", Pool: "team-a"},
		{Name: "ap-northeast-2", Kind: "aws"},
		{Name: "eu-west-1", Kind: "aws"},
	}
	if len(items) != 1 || items[0].Project != "123456789012" || !slices.Equal(items[0].Regions, want) {
		t.Fatalf("mapped project: %+v", items)
	}
	for _, private := range []string{
		"210987654321", "345678901234", "canary-role", "canary-external",
		store.DescribeSecret("canary-external-one").Fingerprint, store.DescribeSecret("pve-other-secret").Fingerprint,
		store.DescribeSecret("pve-test-secret").Fingerprint, "canary-token-id", "10.20.30.40", "awsAccounts", "roleArn",
	} {
		if strings.Contains(body, private) {
			t.Fatalf("project list exposes %q: %s", private, body)
		}
	}
}

func TestListProjectsUnreadableAWSAccountKeepsProxmoxRegions(t *testing.T) {
	e, _, app, _ := accountFixture(t)
	b := store.NewMemory()
	g := store.New(b)
	if _, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-lab-1"}); err != nil {
		t.Fatal(err)
	}
	e.h.(*handler).registry = g
	if _, err := g.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "210987654321", RoleARN: "arn:aws:iam::210987654321:role/canary-role-one", AllowedRegions: []string{"us-east-1"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(t.Context(), "aws-accounts/345678901234", []byte("private-undecodable-account")); err != nil {
		t.Fatal(err)
	}
	pve := []projectRegion{{Name: "pve-lab-1", Kind: "pve", Pool: "team-a"}}
	for _, mapped := range [][]string{{"210987654321", "999999999999"}, {"210987654321", "345678901234"}} {
		v, err := g.Projects().Get(t.Context(), "123456789012")
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		v.Project, v.Pools, v.AWSAccounts = "123456789012", []store.ProjectPool{{Region: "pve-lab-1", Pool: "team-a"}}, mapped
		if _, err := g.Projects().Put(t.Context(), v); err != nil {
			t.Fatal(err)
		}
		items, _ := listProjectsCall(t, e, http.StatusOK)
		if len(items) != 1 || !slices.Equal(items[0].Regions, pve) {
			t.Fatalf("accounts %v: %+v, want only the Proxmox region", mapped, items)
		}
	}
	if strings.Count(app.String(), "a mapped AWS account is unreadable") != 2 {
		t.Fatalf("want one warning per listing: %s", app)
	}
	for _, private := range []string{"210987654321", "345678901234", "999999999999", "private-undecodable-account"} {
		if strings.Contains(app.String(), private) {
			t.Fatalf("warning contains %q: %s", private, app)
		}
	}
}

type failedProjectStore struct {
	store.Backend
	err error
}

func (b failedProjectStore) Get(context.Context, string) (store.Entry, error) {
	return store.Entry{}, b.err
}

func TestListProjectsRegistryFailureIsSafe(t *testing.T) {
	e, _ := adminFixture(t)
	const cause = "dial tcp 10.9.9.9:2379: connect: connection refused"
	e.h.(*handler).registry = store.New(failedProjectStore{Backend: store.NewMemory(), err: errors.New(cause)})
	_, body := listProjectsCall(t, e, http.StatusServiceUnavailable)
	if !strings.Contains(body, "project registry read failed") || strings.Contains(body, "10.9.9.9") ||
		strings.Contains(body, "2379") {
		t.Fatalf("registry failure: %s", body)
	}

	e.h.(*handler).registry = nil
	_, body = listProjectsCall(t, e, http.StatusServiceUnavailable)
	if !strings.Contains(body, "admin registry unavailable") {
		t.Fatalf("no registry: %s", body)
	}
}

func TestListProjectsRefusesQueryAndDeniedCaller(t *testing.T) {
	e, _ := adminFixture(t)
	bearer := map[string]string{"Authorization": "Bearer tok"}
	rec := e.do(t, http.MethodGet, projectsPath+"?project=123456789012", "", bearer)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "query parameters are not supported") {
		t.Fatalf("query: %d %s", rec.Code, rec.Body)
	}

	user, _ := e.login(t)
	if rec := e.do(t, http.MethodGet, projectsPath, "", nil, user); rec.Code != http.StatusForbidden {
		t.Fatalf("caller without vws:ListProjects: %d %s", rec.Code, rec.Body)
	}
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "projects",
		`{"Statement":[{"Effect":"Allow","Action":"vws:ListProjects","Resource":"*"}]}`,
		backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, http.MethodGet, projectsPath, "", nil, user); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"project":"123456789012"`) {
		t.Fatalf("caller with vws:ListProjects: %d %s", rec.Code, rec.Body)
	}
}
