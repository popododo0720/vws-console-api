package regionset_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

// launchKey is the public key regionalKeys returns for "login".
const launchKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEC8lf7xuF2l"

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
	if len(q.Names) != 0 && q.Names[0] == "keyless" {
		return resource.Page[resource.KeyPair]{Items: []resource.KeyPair{{Name: "keyless"}}}, nil
	}
	return resource.Page[resource.KeyPair]{Items: []resource.KeyPair{{Name: "login", PublicKey: launchKey}}}, nil
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
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
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
	// IAM without the key's public key is refused before any region request.
	_, err = set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{KeyName: "keyless"})
	if resource.CodeOf(err) != resource.CodeInternal || calls.Load() != 0 {
		t.Fatalf("launch key without public key: region calls=%d err=%v", calls.Load(), err)
	}
	_, err = set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{KeyName: "login"})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("known launch key: region calls=%d err=%v", calls.Load(), err)
	}
	// Without a key name nothing is sent, even when the caller set a key.
	_, err = set.Compute.RunInstances(t.Context(), m, resource.RunInstancesRequest{PublicKey: launchKey})
	if err != nil || calls.Load() != 2 {
		t.Fatalf("launch without key: region calls=%d err=%v", calls.Load(), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(bodies[0], `"publicKey":"`+launchKey+`"`) {
		t.Fatalf("the region request does not carry the key: %s", bodies[0])
	}
	if strings.Contains(bodies[1], "publicKey") || strings.Contains(bodies[1], "AAAAC3") {
		t.Fatalf("a launch without a key name carries one: %s", bodies[1])
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
