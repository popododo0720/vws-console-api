package sigv4

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// The client address goes to the authenticator (AuthenticateRequest.source_ip)
// and what the authenticator knows about the principal reaches the caller.
func TestSourceIPAndPrincipalRef(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	cred := cred(t)
	ref := resource.PrincipalRef{UniqueID: "AIDABOB", Resource: "projects/123456789012/users/bob", ProofKind: resource.ProofSigV4, Proof: "p"}
	var seen AuthRequest
	v := NewVerifier(Verifier{Service: ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: authFunc(func(ctx context.Context, r AuthRequest) (Identity, error) {
			seen = r
			if !r.VerifiedBy(cred.Secret) {
				return Identity{}, resource.Unauthenticated("signature mismatch")
			}
			return Identity{Account: cred.Account, Principal: "arn:vws:iam::123456789012:user/bob", Ref: ref}, nil
		})})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeVpcs&Version=2016-11-15"))
	req.Host = "127.0.0.1:8081"
	req.RemoteAddr = "192.0.2.7:40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := Sign(req, cred, ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	caller, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if seen.SourceIP != "192.0.2.7" {
		t.Errorf("source ip %q", seen.SourceIP)
	}
	if caller.Ref != ref || caller.Principal != "arn:vws:iam::123456789012:user/bob" {
		t.Errorf("caller %+v", caller)
	}
}
