package console

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// refIAM stands in for the vws-iam gRPC client: its sessions carry the
// vws-iam principal reference, and it records what Authorize was sent.
type refIAM struct {
	iam.Client
	mu   sync.Mutex
	seen []iam.Principal
}

func (r *refIAM) ValidateSession(ctx context.Context, token string) (iam.Session, error) {
	s, err := r.Client.ValidateSession(ctx, token)
	if err != nil {
		return s, err
	}
	s.Principal.Ref = resource.PrincipalRef{UniqueID: "AIDABOB", Resource: "projects/123456789012/users/bob", ProofKind: resource.ProofSession, Proof: token}
	return s, nil
}

func (r *refIAM) Authorize(ctx context.Context, req iam.Request) (iam.Decision, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Principal)
	r.mu.Unlock()
	return r.Client.Authorize(ctx, req)
}

// A cookie session's principal reaches Authorize with the reference vws-iam
// returned from ValidateSession, so vws-iam can recheck it.
func TestSessionCallerKeepsThePrincipalRef(t *testing.T) {
	e := newLoginEnv(t)
	ref := &refIAM{Client: iam.WithRoot(e.root, e.fake)}
	e.h = New(Config{Service: cloudFor(t), IAM: ref})
	sess, _ := e.login(t)
	if rec := e.do(t, http.MethodGet, "/api/v1/instances", "", nil, sess); rec.Code != http.StatusOK {
		t.Fatalf("list instances %d %s", rec.Code, rec.Body)
	}
	ref.mu.Lock()
	defer ref.mu.Unlock()
	if len(ref.seen) == 0 {
		t.Fatal("Authorize not called")
	}
	got := ref.seen[len(ref.seen)-1].Ref
	if got.UniqueID != "AIDABOB" || got.ProofKind != resource.ProofSession || got.Proof != sess.Value {
		t.Errorf("principal ref at Authorize %+v", got)
	}
}
