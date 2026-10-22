package grpcclient

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestKeyPairCreateConflictsMapByReason is #291. Compute answers a key pair
// create with a conflict for causes EC2 tells apart. A lost optimistic
// concurrency race (ETAG_MISMATCH, GENERATION_CONFLICT, or Aborted with no
// reason) is transient: Unavailable, which EC2 clients retry. A refusal for
// the current state (DEPENDENCY_NOT_READY, DEPENDENCY_MISSING, or
// FailedPrecondition with no reason) is a key pair conflict, which EC2
// reports as IncorrectState. Neither is an instance error.
func TestKeyPairCreateConflictsMapByReason(t *testing.T) {
	pub := mustPublicKey(t)
	bare := func(code codes.Code) func() error {
		return func() error { return status.Error(code, "refused") }
	}
	reason := func(code codes.Code, r string) func() error {
		return func() error { return vwsStatus(code, r, "refused") }
	}
	for _, tc := range []struct {
		name   string
		refuse func() error
		want   resource.Code
	}{
		{"etag mismatch", reason(codes.Aborted, "ETAG_MISMATCH"), resource.CodeUnavailable},
		{"generation conflict", reason(codes.Aborted, "GENERATION_CONFLICT"), resource.CodeUnavailable},
		{"aborted without a reason", bare(codes.Aborted), resource.CodeUnavailable},
		{"dependency not ready", reason(codes.FailedPrecondition, "DEPENDENCY_NOT_READY"), resource.CodeConflict},
		{"dependency missing", reason(codes.FailedPrecondition, "DEPENDENCY_MISSING"), resource.CodeConflict},
		{"failed precondition without a reason", bare(codes.FailedPrecondition), resource.CodeConflict},
	} {
		for _, imported := range []bool{true, false} {
			label := tc.name + ", create"
			req := resource.CreateKeyPairRequest{Name: "refused", Type: resource.KeyTypeEd25519}
			if imported {
				label = tc.name + ", import"
				req = resource.CreateKeyPairRequest{Name: "refused", PublicKey: pub}
			}
			t.Run(label, func(t *testing.T) {
				client, world := dialKeyWorld(t)
				world.refuse = func(*computev1.CreateKeyPairRequest) error { return tc.refuse() }
				m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "refused-token", Fingerprint: "fp"}
				got, err := client.CreateKeyPair(context.Background(), m, req)
				var re *resource.Error
				if !errors.As(err, &re) || re.Code != tc.want || re.Kind != resource.KindKeyPair || len(got.Items) != 0 {
					t.Fatalf("want %v of KindKeyPair and no items, got %#v %+v", tc.want, err, got.Items)
				}
				if re.ID != "refused" {
					t.Fatalf("the error names %q, want the key pair name", re.ID)
				}
			})
		}
	}
}
