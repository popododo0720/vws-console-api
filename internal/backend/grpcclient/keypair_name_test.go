package grpcclient

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func (w *keyWorld) DeleteKeyPair(
	_ context.Context, req *computev1.DeleteKeyPairRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.keys[req.GetName()]; !ok {
		return nil, status.Error(codes.NotFound, "key pair "+req.GetName()+" not found")
	}
	delete(w.keys, req.GetName())
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	verb := commonv1.OperationVerb_OPERATION_VERB_DELETE
	return runningNamed(projectID, req.GetRequestId(), req.GetName(), verb, keyWorldNow)
}

// requireDuplicate checks the error EC2 reports as InvalidKeyPair.Duplicate.
func requireDuplicate(t *testing.T, label string, got resource.Accepted[resource.KeyPair], err error) {
	t.Helper()
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeAlreadyExists || re.Kind != resource.KindKeyPair {
		t.Fatalf("%s: want AlreadyExists of KindKeyPair, got %#v", label, err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("%s: a refused create returned %d items", label, len(got.Items))
	}
}

// TestConcurrentCreatesOfOneNameMakeOneKeyPair is #273. EC2 key pair names
// are unique per account. Sixteen creates of one name under sixteen client
// tokens race. Compute's create is atomic per key pair id, so the id must
// name the key pair, not the token: exactly one create succeeds and the rest
// are InvalidKeyPair.Duplicate.
func TestConcurrentCreatesOfOneNameMakeOneKeyPair(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	account := mustAccount(t)
	const n = 16
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		won  int
		errs []error
	)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := backend.Mutation{
				Scope: backend.Scope{Account: account}, Key: fmt.Sprintf("token-%d", i), Fingerprint: fmt.Sprintf("fp-%d", i),
			}
			req := resource.CreateKeyPairRequest{Name: "deploy", Type: resource.KeyTypeEd25519}
			got, err := client.CreateKeyPair(ctx, m, req)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won++
				return
			}
			if len(got.Items) != 0 {
				err = fmt.Errorf("refused create returned %d items: %w", len(got.Items), err)
			}
			errs = append(errs, err)
		}()
	}
	wg.Wait()
	if won != 1 || len(world.keys) != 1 {
		t.Fatalf("%d of %d same-name creates succeeded and compute stored %d key pairs, want 1 and 1",
			won, n, len(world.keys))
	}
	for _, err := range errs {
		requireDuplicate(t, "losing create", resource.Accepted[resource.KeyPair]{}, err)
	}
}

// TestCreateRefusesTheNameOfAKeyPairWithATokenID is #273. Key pairs created
// before the name-derived id carry an id derived from their client token.
// Their name must still block a create under a new token, and they must stay
// listed, described by id and name, and deletable.
func TestCreateRefusesTheNameOfAKeyPairWithATokenID(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	account := mustAccount(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldID := derivedID("key-", "old-mutation-key", "key")
	oldName := keyPairName(project(account), oldID)
	world.keys[oldName] = &computev1.KeyPair{
		Name: oldName, Labels: nameLabels("legacy"), Spec: &computev1.KeyPairSpec{PublicKey: pair.Public},
	}

	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "new-token", Fingerprint: "new-fp"}
	legacy := resource.CreateKeyPairRequest{Name: "legacy", Type: resource.KeyTypeEd25519}
	got, err := client.CreateKeyPair(ctx, m, legacy)
	requireDuplicate(t, "create over an old key pair's name", got, err)
	if len(world.keys) != 1 {
		t.Fatalf("compute stored %d key pairs, want the old one only", len(world.keys))
	}

	scope := backend.Scope{Account: account}
	byName, err := client.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{Names: []string{"legacy"}})
	if err != nil || len(byName.Items) != 1 || byName.Items[0].ID.String() != oldID {
		t.Fatalf("describe by name: %v, %+v", err, byName.Items)
	}
	id, err := resource.Parse[resource.KeyPairID](oldID)
	if err != nil {
		t.Fatal(err)
	}
	byID, err := client.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{IDs: []resource.KeyPairID{id}})
	if err != nil || len(byID.Items) != 1 || byID.Items[0].Name != "legacy" {
		t.Fatalf("describe by id: %v, %+v", err, byID.Items)
	}
	del := backend.Mutation{Scope: scope, Key: "delete-token", Fingerprint: "delete-fp"}
	if _, err := client.DeleteKeyPair(ctx, del, resource.DeleteKeyPairRequest{Name: "legacy"}); err != nil {
		t.Fatalf("delete by name: %v", err)
	}
	if len(world.keys) != 0 {
		t.Fatalf("delete left %d key pairs", len(world.keys))
	}
	again, err := client.CreateKeyPair(ctx, m, legacy)
	if err != nil || len(again.Items) != 1 || again.Items[0].Material == "" {
		t.Fatalf("create after the old key pair is gone: %v, %+v", err, again.Items)
	}
}
