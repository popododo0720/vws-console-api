package grpcclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// keyWorld stores key pairs the way vws-compute does: a request id replays
// only the exact request it first carried, and any other body under it is
// IDEMPOTENCY_CONFLICT. It keeps no private key, because none is sent.
type keyWorld struct {
	computev1.UnimplementedKeyPairServiceServer
	mu       sync.Mutex
	requests map[string][32]byte
	keys     map[string]*computev1.KeyPair
	sent     []string
	// afterList, when set, runs after ListKeyPairs takes its snapshot and
	// before it answers, so a test can interleave other calls there.
	afterList func()
	// afterGet runs after GetKeyPair answers and before the reply is sent,
	// and afterCreate likewise after CreateKeyPair, so a test can land a call
	// between a client's lookup and its create, or between its create and
	// whatever it does next (#284).
	afterGet, afterCreate func()
	// refuse, when set, answers a CreateKeyPair before compute looks at it.
	refuse func(*computev1.CreateKeyPairRequest) error
}

func (w *keyWorld) CreateKeyPair(
	ctx context.Context, req *computev1.CreateKeyPairRequest,
) (*longrunningpb.Operation, error) {
	op, err := w.createKeyPair(ctx, req)
	w.mu.Lock()
	hook := w.afterCreate
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	return op, err
}

func (w *keyWorld) createKeyPair(
	_ context.Context, req *computev1.CreateKeyPairRequest,
) (*longrunningpb.Operation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.refuse != nil {
		if err := w.refuse(req); err != nil {
			return nil, err
		}
	}
	w.sent = append(w.sent, req.GetKeyPair().GetSpec().GetPublicKey())
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	name := keyPairName(projectID, req.GetKeyPairId())
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	sum := sha256.Sum256(body)
	if prior, ok := w.requests[req.GetRequestId()]; ok {
		if prior != sum {
			return nil, vwsStatus(codes.Aborted, "IDEMPOTENCY_CONFLICT", "request id was used for a different request")
		}
		return runningNamed(projectID, req.GetRequestId(), name, createVerb, keyWorldNow)
	}
	if _, ok := w.keys[name]; ok {
		return nil, status.Error(codes.AlreadyExists, "key pair "+name+" already exists")
	}
	w.requests[req.GetRequestId()] = sum
	stored := proto.Clone(req.GetKeyPair()).(*computev1.KeyPair)
	stored.Name = name
	w.keys[name] = stored
	return runningNamed(projectID, req.GetRequestId(), name, createVerb, keyWorldNow)
}

func (w *keyWorld) GetKeyPair(
	_ context.Context, req *computev1.GetKeyPairRequest,
) (*computev1.KeyPair, error) {
	w.mu.Lock()
	kp, ok := w.keys[req.GetName()]
	hook := w.afterGet
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	if ok {
		return kp, nil
	}
	return nil, status.Error(codes.NotFound, "key pair "+req.GetName()+" not found")
}

func (w *keyWorld) ListKeyPairs(
	context.Context, *computev1.ListKeyPairsRequest,
) (*computev1.ListKeyPairsResponse, error) {
	w.mu.Lock()
	out := &computev1.ListKeyPairsResponse{}
	for _, kp := range w.keys {
		out.KeyPairs = append(out.KeyPairs, kp)
	}
	hook := w.afterList
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	return out, nil
}

const createVerb = commonv1.OperationVerb_OPERATION_VERB_CREATE

var keyWorldNow = time.Unix(1_700_000_000, 0)

func dialKeyWorld(t *testing.T) (computeClient, *keyWorld) {
	t.Helper()
	world := &keyWorld{requests: map[string][32]byte{}, keys: map[string]*computev1.KeyPair{}}
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterKeyPairServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///compute",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{keys: computev1.NewKeyPairServiceClient(conn)}}, world
}

// TestCreatedKeyIsNotDerivedFromTheRequest is #220. The same account,
// client token, and request on two deployments must give unrelated keys. A
// key that is a function of the request would let anyone holding the token
// rebuild the private key.
func TestCreatedKeyIsNotDerivedFromTheRequest(t *testing.T) {
	ctx := context.Background()
	m := backend.Mutation{
		Scope: backend.Scope{Account: mustAccount(t)}, Key: "same-mutation-key", Fingerprint: "same-fingerprint",
	}
	for _, typ := range []resource.KeyType{resource.KeyTypeRSA, resource.KeyTypeEd25519} {
		req := resource.CreateKeyPairRequest{Name: "admin", Type: typ}
		a, aw := dialKeyWorld(t)
		b, bw := dialKeyWorld(t)
		first, err := a.CreateKeyPair(ctx, m, req)
		if err != nil {
			t.Fatalf("%s first: %v", typ, err)
		}
		second, err := b.CreateKeyPair(ctx, m, req)
		if err != nil {
			t.Fatalf("%s second: %v", typ, err)
		}
		if first.Items[0].Material == "" || second.Items[0].Material == "" {
			t.Fatalf("%s: a create returned no private key", typ)
		}
		if first.Items[0].Material == second.Items[0].Material {
			t.Fatalf("%s: the same request gave the same private key", typ)
		}
		if aw.sent[0] == bw.sent[0] || first.Items[0].Fingerprint == second.Items[0].Fingerprint {
			t.Fatalf("%s: the same request gave the same public key", typ)
		}
		other, err := a.CreateKeyPair(ctx, backend.Mutation{Scope: m.Scope, Key: "other-mutation-key", Fingerprint: "other"},
			resource.CreateKeyPairRequest{Name: "admin-2", Type: typ})
		if err != nil {
			t.Fatalf("%s other: %v", typ, err)
		}
		if other.Items[0].Material == first.Items[0].Material || aw.sent[1] == aw.sent[0] {
			t.Fatalf("%s: a different token gave the same key", typ)
		}
	}
}

// TestCreateKeyPairReplayDoesNotReturnTheKey is #220. EC2 CreateKeyPair has
// no client token and returns the private key once. A second create of the
// name is InvalidKeyPair.Duplicate. A retry under the same token is that
// second create, so it never carries a private key. A reused token for a
// free name creates that key pair (#268).
func TestCreateKeyPairReplayDoesNotReturnTheKey(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "replay-key", Fingerprint: "replay-fp"}
	req := resource.CreateKeyPairRequest{Name: "admin", Type: resource.KeyTypeEd25519}
	first, err := client.CreateKeyPair(ctx, m, req)
	if err != nil || first.Items[0].Material == "" {
		t.Fatalf("first: %v, %d items", err, len(first.Items))
	}
	again, err := client.CreateKeyPair(ctx, m, req)
	if resource.CodeOf(err) != resource.CodeAlreadyExists {
		resent := len(again.Items) > 0 && again.Items[0].Material != ""
		t.Fatalf("replay: want AlreadyExists, got %v, %d items, key sent again: %t", err, len(again.Items), resent)
	}
	var re *resource.Error
	if !errors.As(err, &re) || re.Kind != resource.KindKeyPair {
		t.Fatalf("replay error kind: %#v", err)
	}
	if len(again.Items) != 0 {
		t.Fatalf("replay returned %d items", len(again.Items))
	}
	other := m
	other.Fingerprint = "different-request"
	web, err := client.CreateKeyPair(ctx, other, resource.CreateKeyPairRequest{Name: "web", Type: resource.KeyTypeEd25519})
	if err != nil || len(web.Items) != 1 || web.Items[0].Material == "" ||
		web.Items[0].Material == first.Items[0].Material {
		t.Fatalf("reused token, free name: want a new key pair (#268), got %v %+v", err, web.Items)
	}
	if len(world.keys) != 2 {
		t.Fatalf("stored %d key pairs, want 2", len(world.keys))
	}
}
