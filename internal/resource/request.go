package resource

import (
	"encoding/json"
	"fmt"
	"time"
)

// Request is a long-running mutation input. Normalize returns the canonical
// form that idempotency fingerprints.
type Request[R any] interface {
	Action() Action
	Normalize() (R, error)
}

// Query is a read or a synchronous call. Normalize returns the canonical form.
type Query[Q any] interface {
	Normalize() (Q, error)
}

// Caller is who the surface authenticated. The kernel scopes every call to Account.
type Caller struct {
	Account AccountID
	Subject string
	Region  string
	// Principal is the IAM ARN the request is authorized as, such as
	// arn:vws:iam::123456789012:user/bob. Root marks the account root.
	Principal string
	Root      bool
	// Ref is what the identity service needs to recheck this principal.
	// Static and fake authenticators leave it empty.
	Ref PrincipalRef
}

// Proof kinds of a PrincipalRef.
const (
	// ProofSigV4 is a serialized vws-iam AuthenticateRequest.
	ProofSigV4 = "sigv4"
	// ProofSession is a console session token.
	ProofSession = "session"
)

// PrincipalRef is the part of a vws-iam Principal beyond account, ARN and
// root: vws-iam rechecks unique id, resource and session name on Authorize.
// Proof lets vws-iam re-authenticate the caller itself on STS calls, which
// take the caller from the request's authentication field. SessionContext
// is the value vws-iam sealed into the Principal it returned; Authorize gets
// it back unchanged and refuses an assumed role without it. Both are
// credential-bound: String, GoString and MarshalJSON print them as
// [REDACTED], so a %v, a slog attribute or a JSON record never holds them.
type PrincipalRef struct {
	UniqueID       string
	Resource       string
	SessionName    string
	MFA            bool
	AuthTime       time.Time
	ProofKind      string
	Proof          string
	SessionContext string
}

const redacted = "[REDACTED]"

type printedRef PrincipalRef

func (r PrincipalRef) printed() printedRef {
	p := printedRef(r)
	if p.Proof != "" {
		p.Proof = redacted
	}
	if p.SessionContext != "" {
		p.SessionContext = redacted
	}
	return p
}

// String implements fmt.Stringer without the credential-bound values.
func (r PrincipalRef) String() string { return fmt.Sprintf("%+v", r.printed()) }

// GoString implements fmt.GoStringer without the credential-bound values.
func (r PrincipalRef) GoString() string { return "resource.PrincipalRef" + r.String() }

// MarshalJSON implements json.Marshaler without the credential-bound values.
func (r PrincipalRef) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(r.printed())
	if err != nil {
		return nil, fmt.Errorf("marshal principal ref: %w", err)
	}
	return b, nil
}

// Owned is a result that names its account. The kernel rejects a result whose
// owner is not the caller.
type Owned interface {
	Owner() AccountID
	Identity() string
}
