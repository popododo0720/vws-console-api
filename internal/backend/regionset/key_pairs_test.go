package regionset_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type regionalKeys struct {
	backend.Compute
	scope backend.Scope
}

func (k *regionalKeys) DescribeKeyPairs(
	_ context.Context, s backend.Scope, q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	k.scope = s
	if len(q.Names) != 0 && q.Names[0] == "missing" {
		return resource.Page[resource.KeyPair]{}, resource.NotFound(resource.KindKeyPair, q.Names[0])
	}
	return resource.Page[resource.KeyPair]{Items: []resource.KeyPair{{Name: "login"}}}, nil
}

func (k *regionalKeys) CreateKeyPair(
	_ context.Context, m backend.Mutation, req resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	k.scope = m.Scope
	return resource.Accepted[resource.KeyPair]{Items: []resource.KeyPair{{Name: req.Name}}}, nil
}

func (k *regionalKeys) DeleteKeyPair(
	_ context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	k.scope = m.Scope
	return resource.Accepted[resource.KeyPair]{Items: []resource.KeyPair{{Name: req.Name}}}, nil
}

func TestIAMKeyPairsNeverCallRegion(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := regionapi.NewClient(server.URL, &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: server.TLS.Certificates,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	keys := new(regionalKeys)
	set, err := regionset.New(catalog(), func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
		return client, nil
	}, keys)
	if err != nil {
		t.Fatal(err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	m := backend.Mutation{Scope: backend.Scope{Account: account, Region: "pve-a-1"}, Key: "retry"}
	for range 2 {
		page, err := set.Compute.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Name != "login" || keys.scope != m.Scope {
			t.Fatalf("IAM inventory = %+v %v", page, err)
		}
		for _, public := range []string{"", "public-key"} {
			_, err := set.Compute.CreateKeyPair(t.Context(), m, resource.CreateKeyPairRequest{Name: "login", PublicKey: public})
			if err != nil || keys.scope != m.Scope {
				t.Fatalf("IAM create/import = %v", err)
			}
		}
		if _, err := set.Compute.DeleteKeyPair(t.Context(), m, resource.DeleteKeyPairRequest{Name: "login"}); err != nil {
			t.Fatal(err)
		}
		_, err = set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{KeyName: "missing"})
		if resource.CodeOf(err) != resource.CodeNotFound || resource.AsError(err).Kind != resource.KindKeyPair {
			t.Fatalf("missing launch key = %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("IAM key pairs made %d regionapi requests", calls.Load())
	}
	_, err = set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{KeyName: "login"})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("known launch key: region calls=%d err=%v", calls.Load(), err)
	}
}

func TestRegionsKeyMutationsRequireIAM(t *testing.T) {
	set := newSet(t, catalog(), func(context.Context, string, string, backend.Scope, any, any) error {
		t.Fatal("unsupported key action reached a region")
		return nil
	})
	m := backend.Mutation{Scope: backend.Scope{Region: "pve-a-1"}}
	_, createErr := set.Compute.CreateKeyPair(t.Context(), m, resource.CreateKeyPairRequest{Name: "login"})
	_, deleteErr := set.Compute.DeleteKeyPair(t.Context(), m, resource.DeleteKeyPairRequest{Name: "login"})
	_, launchErr := set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{KeyName: "login"})
	for _, err := range []error{createErr, deleteErr, launchErr} {
		if !resource.IsUnsupported(resource.AsError(err)) {
			t.Fatalf("without IAM = %v", err)
		}
	}
}
