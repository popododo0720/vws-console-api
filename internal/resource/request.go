package resource

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
}

// Owned is a result that names its account. The kernel rejects a result whose
// owner is not the caller.
type Owned interface {
	Owner() AccountID
	Identity() string
}
