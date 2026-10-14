package resource

import "time"

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
// take the caller from the request's authentication field; it is a
// credential and is never logged.
type PrincipalRef struct {
	UniqueID    string
	Resource    string
	SessionName string
	MFA         bool
	AuthTime    time.Time
	ProofKind   string
	Proof       string
}

// Owned is a result that names its account. The kernel rejects a result whose
// owner is not the caller.
type Owned interface {
	Owner() AccountID
	Identity() string
}
