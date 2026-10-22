package grpcclient

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// TestImportRetryRacingADeleteImportsAgain is #284. An ImportKeyPair retry
// under its token reads the live key pair's import nonce, then sends the
// request id that nonce names. If DeleteKeyPair lands after that read,
// compute answers the retry from the deleted key pair's retained record, so
// the retry reports a key pair that no longer exists. EC2 ImportKeyPair takes
// no client token: once the name is free the retry must import it again, and
// once another key pair holds the name it is InvalidKeyPair.Duplicate.
func TestImportRetryRacingADeleteImportsAgain(t *testing.T) {
	ours := mustPublicKey(t)
	theirs := mustPublicKey(t)
	for _, tc := range []struct {
		name string
		// between picks the hook the delete lands in: after the retry's
		// nonce read, or after its create.
		between string
		// legacy starts from a key pair imported before #279, with no nonce.
		legacy bool
		// retake imports another key under another token after the delete.
		retake bool
	}{
		{name: "delete after the nonce read", between: "get"},
		{name: "delete after the create", between: "create"},
		{name: "delete after the nonce read of a key pair without a nonce", between: "get", legacy: true},
		{name: "delete after the create of a key pair without a nonce", between: "create", legacy: true},
		{name: "delete and another import after the nonce read", between: "get", retake: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			client, world := dialKeyWorld(t)
			account := mustAccount(t)
			scope := backend.Scope{Account: account}
			m := backend.Mutation{Scope: scope, Key: "race-token", Fingerprint: "race-fp"}
			req := resource.CreateKeyPairRequest{Name: "racer", PublicKey: ours}
			if tc.legacy {
				importBefore279(ctx, t, world, account, m, "racer", ours)
			} else if _, err := client.CreateKeyPair(ctx, m, req); err != nil {
				t.Fatalf("first import: %v", err)
			}

			var fired atomic.Bool
			hook := func() {
				if !fired.CompareAndSwap(false, true) {
					return
				}
				del := backend.Mutation{Scope: scope, Key: "race-delete", Fingerprint: "race-delete-fp"}
				if _, err := client.DeleteKeyPair(ctx, del, resource.DeleteKeyPairRequest{Name: "racer"}); err != nil {
					t.Errorf("delete: %v", err)
				}
				if tc.retake {
					other := backend.Mutation{Scope: scope, Key: "race-other", Fingerprint: "race-other-fp"}
					if _, err := client.CreateKeyPair(ctx, other,
						resource.CreateKeyPairRequest{Name: "racer", PublicKey: theirs}); err != nil {
						t.Errorf("import of another key: %v", err)
					}
				}
			}
			world.mu.Lock()
			if tc.between == "get" {
				world.afterGet = hook
			} else {
				world.afterCreate = hook
			}
			world.mu.Unlock()

			got, err := client.CreateKeyPair(ctx, m, req)
			if !fired.Load() {
				t.Fatal("the delete never landed")
			}
			world.mu.Lock()
			world.afterGet, world.afterCreate = nil, nil
			world.mu.Unlock()
			listed, lerr := client.DescribeKeyPairs(ctx, scope,
				resource.KeyPairQuery{Names: []string{"racer"}, Page: resource.PageRequest{Size: 50}})
			if lerr != nil || len(listed.Items) != 1 {
				t.Fatalf("describe after the retry: %v %+v", lerr, listed.Items)
			}
			if tc.retake {
				requireDuplicate(t, "retry while another key pair holds the name", got, err)
				if listed.Items[0].Fingerprint == fingerprintOf(t, ours) {
					t.Fatalf("the retry replaced the other key pair: %+v", listed.Items)
				}
				return
			}
			if err != nil || len(got.Items) != 1 {
				t.Fatalf("retry after the delete: want an import, got %v %+v", err, got.Items)
			}
			if listed.Items[0].ID != got.Items[0].ID || listed.Items[0].Fingerprint != fingerprintOf(t, ours) {
				t.Fatalf("retry returned %s, but %+v is live", got.Items[0].ID, listed.Items)
			}
			world.mu.Lock()
			n := len(world.keys)
			world.mu.Unlock()
			if n != 1 {
				t.Fatalf("compute holds %d key pairs, want 1", n)
			}
		})
	}
}

// TestImportConflictsMapByCause is #284. Compute answers a key pair create
// with a conflict for several causes. Only a name collision is EC2's
// InvalidKeyPair.Duplicate; every other conflict keeps its own code, so a
// broken request id or a stale resource is not reported as a taken name.
func TestImportConflictsMapByCause(t *testing.T) {
	pub := mustPublicKey(t)
	for _, tc := range []struct {
		name   string
		reason string
		code   codes.Code
		// generate makes a CreateKeyPair instead of an ImportKeyPair.
		generate bool
		want     resource.Code
	}{
		{name: "name taken", reason: "ALREADY_EXISTS", code: codes.AlreadyExists, want: resource.CodeAlreadyExists},
		{
			name: "request id reused for a free name", reason: "IDEMPOTENCY_CONFLICT", code: codes.Aborted,
			want: resource.CodeIdempotencyMismatch,
		},
		{
			name: "request id reused by a generated create", reason: "IDEMPOTENCY_CONFLICT", code: codes.Aborted,
			generate: true, want: resource.CodeIdempotencyMismatch,
		},
		{name: "etag mismatch", reason: "ETAG_MISMATCH", code: codes.Aborted, want: resource.CodeConflict},
		{name: "generation conflict", reason: "GENERATION_CONFLICT", code: codes.Aborted, want: resource.CodeConflict},
		{
			name: "dependency not ready", reason: "DEPENDENCY_NOT_READY", code: codes.FailedPrecondition,
			want: resource.CodeConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			client, world := dialKeyWorld(t)
			world.refuse = func(*computev1.CreateKeyPairRequest) error {
				return vwsStatus(tc.code, tc.reason, "refused")
			}
			m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "conflict-token", Fingerprint: "fp"}
			req := resource.CreateKeyPairRequest{Name: "conflicted", PublicKey: pub}
			if tc.generate {
				req = resource.CreateKeyPairRequest{Name: "conflicted", Type: resource.KeyTypeEd25519}
			}
			got, err := client.CreateKeyPair(ctx, m, req)
			var re *resource.Error
			if !errors.As(err, &re) || re.Code != tc.want || len(got.Items) != 0 {
				t.Fatalf("%s: want %v, got %#v %+v", tc.reason, tc.want, err, got.Items)
			}
			if tc.want == resource.CodeAlreadyExists && re.Kind != resource.KindKeyPair {
				t.Fatalf("a name collision must be InvalidKeyPair.Duplicate, got kind %v", re.Kind)
			}
		})
	}
}

// TestImportConflictOnALiveNameIsDuplicate is the name collision of #284
// that compute reports as IDEMPOTENCY_CONFLICT: another key under the token
// of the live key pair names that key pair's request.
func TestImportConflictOnALiveNameIsDuplicate(t *testing.T) {
	ctx := context.Background()
	client, _ := dialKeyWorld(t)
	m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "live-token", Fingerprint: "fp-first"}
	first := resource.CreateKeyPairRequest{Name: "held", PublicKey: mustPublicKey(t)}
	if _, err := client.CreateKeyPair(ctx, m, first); err != nil {
		t.Fatal(err)
	}
	m.Fingerprint = "fp-second"
	got, err := client.CreateKeyPair(ctx, m, resource.CreateKeyPairRequest{Name: "held", PublicKey: mustPublicKey(t)})
	requireDuplicate(t, "another key under the live key pair's token", got, err)
}

// importBefore279 stores the request an import sent before #279: the token's
// request id, and no import nonce.
func importBefore279(
	ctx context.Context, t *testing.T, world *keyWorld, account resource.AccountID, m backend.Mutation, name, pub string,
) {
	t.Helper()
	labels := nameLabels(name)
	labels[labelFingerprint] = m.Fingerprint
	if _, err := world.CreateKeyPair(ctx, &computev1.CreateKeyPairRequest{
		Parent:    regionParent(project(account)),
		KeyPairId: derivedID("key-", account.String(), "key-name", name),
		RequestId: requestUUID(m.Key, "key"),
		KeyPair:   &computev1.KeyPair{Labels: labels, Spec: &computev1.KeyPairSpec{PublicKey: pub}},
	}); err != nil {
		t.Fatal(err)
	}
}

func mustPublicKey(t *testing.T) string {
	t.Helper()
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}

func fingerprintOf(t *testing.T, pub string) string {
	t.Helper()
	parsed, err := sshkey.ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.AWSFingerprint
}

// TestKeyImportConcurrentContract runs the #287 concurrent import table over
// the gRPC client. keyWorld holds each caller's first GetKeyPair until every
// caller has made one, so all of them see the name free and draw their own
// import nonce before any create reaches compute.
func TestKeyImportConcurrentContract(t *testing.T) {
	backendtest.KeyImportConcurrent(t, func(callers int) backend.Set {
		client, world := dialKeyWorld(t)
		world.afterGet = gather(callers)
		return backend.Set{Compute: client}
	})
}

// gather returns a hook that holds its first n calls until all n arrived.
// Later calls pass. A caller that never comes releases the rest after a
// timeout, so a broken client fails the test instead of hanging it.
func gather(n int) func() {
	var (
		mu      sync.Mutex
		arrived int
	)
	all := make(chan struct{})
	return func() {
		mu.Lock()
		arrived++
		k := arrived
		if k == n {
			close(all)
		}
		mu.Unlock()
		if k <= n {
			select {
			case <-all:
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// TestImportThatKeepsLosingRacesIsRetryable bounds the #287 loop. Every
// GetKeyPair answer is out of date by the time the import acts on it: the
// key pair it saw live is gone when it checks, and a name it saw free is
// taken when it creates. The import gives up after three resubmits
// (maxImportAttempts) with a retryable error, not a guess, and makes no key
// pair.
func TestImportThatKeepsLosingRacesIsRetryable(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	account := mustAccount(t)
	id := derivedID("key-", account.String(), "key-name", "flapping")
	name := keyPairName(project(account), id)
	held := &computev1.KeyPair{
		Name: name, Labels: map[string]string{labelImport: "held-nonce"},
		Spec: &computev1.KeyPairSpec{PublicKey: mustPublicKey(t)},
	}
	world.keys[name] = held
	world.afterGet = func() {
		world.mu.Lock()
		defer world.mu.Unlock()
		if _, ok := world.keys[name]; ok {
			delete(world.keys, name)
		} else {
			world.keys[name] = held
		}
	}
	var sent atomic.Int32
	world.refuse = func(req *computev1.CreateKeyPairRequest) error {
		sent.Add(1)
		if req.GetKeyPair().GetLabels()[labelImport] == "held-nonce" {
			return vwsStatus(codes.Aborted, "IDEMPOTENCY_CONFLICT", "request id was used for a different request")
		}
		return vwsStatus(codes.AlreadyExists, "ALREADY_EXISTS", "key pair "+name+" already exists")
	}
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "flap-token", Fingerprint: "flap-fp"}
	got, err := client.CreateKeyPair(ctx, m, resource.CreateKeyPairRequest{Name: "flapping", PublicKey: mustPublicKey(t)})
	if resource.CodeOf(err) != resource.CodeUnavailable || len(got.Items) != 0 {
		t.Fatalf("want a retryable Unavailable, got %v %+v", err, got.Items)
	}
	// The first create and three resubmits (maxImportAttempts).
	const wantCreates = 4
	if n := sent.Load(); n != wantCreates {
		t.Fatalf("sent %d creates, want %d", n, wantCreates)
	}
}
