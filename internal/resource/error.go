package resource

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Code classifies an Error. Surfaces map it to wire codes with an exhaustive switch.
type Code int

// The error codes. CodeUnspecified is the zero value.
const (
	CodeUnspecified Code = iota
	CodeInvalidArgument
	CodeNotFound
	CodeAlreadyExists
	CodeConflict
	CodeIdempotencyMismatch
	CodeUnauthenticated
	CodePermissionDenied
	CodeResourceExhausted
	CodePayloadTooLarge
	CodeUnavailable
	CodeUnimplemented
	CodeInternal
)

// Codes returns every specified code, in declaration order.
func Codes() []Code {
	var out []Code
	for c := Code(1); c.String() != "Unspecified"; c++ {
		out = append(out, c)
	}
	return out
}

// String returns the canonical name, such as "NotFound".
func (c Code) String() string {
	switch c {
	case CodeInvalidArgument:
		return "InvalidArgument"
	case CodeNotFound:
		return "NotFound"
	case CodeAlreadyExists:
		return "AlreadyExists"
	case CodeConflict:
		return "Conflict"
	case CodeIdempotencyMismatch:
		return "IdempotencyMismatch"
	case CodeUnauthenticated:
		return "Unauthenticated"
	case CodePermissionDenied:
		return "PermissionDenied"
	case CodeResourceExhausted:
		return "ResourceExhausted"
	case CodePayloadTooLarge:
		return "PayloadTooLarge"
	case CodeUnavailable:
		return "Unavailable"
	case CodeUnimplemented:
		return "Unimplemented"
	case CodeInternal:
		return "Internal"
	case CodeUnspecified:
		return "Unspecified"
	default:
		return "Unspecified"
	}
}

// Error is the domain error every layer returns. The cause is for logs and
// never appears in a wire body.
type Error struct {
	Code    Code
	Kind    Kind
	ID      string
	Field   string
	Message string
	cause   error
	// owned marks a bucket create refused because the caller already owns
	// the name, as opposed to a name another account holds (#315).
	owned bool
	// duplicate marks a security group rule that already exists, which EC2
	// answers as InvalidPermission.Duplicate (#272).
	duplicate bool
	// invalid refines CodeInvalidArgument for EC2, which tells a missing
	// parameter and a bad combination apart from a bad value.
	invalid invalidReason
	// permissionMissing marks a security group rule that is not there, which
	// EC2 answers as InvalidPermission.NotFound (#272).
	permissionMissing bool
	// rulesLimit marks a security group that would hold more than
	// MaxIngressRules inbound rules, which EC2 answers as
	// RulesPerSecurityGroupLimitExceeded.
	rulesLimit bool
	// deleting marks a bucket create refused because the caller's own bucket
	// of that name is still being deleted (#321).
	deleting bool
}

type invalidReason uint8

const (
	invalidValue invalidReason = iota
	invalidMissing
	invalidCombination
	invalidUnsupported
	invalidTagLimit
	invalidTaggedID
	invalidAttachmentLimit
	invalidVpcRange
)

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%v: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%v: %s", e.Code, e.Message)
}

// Unwrap returns the internal cause.
func (e *Error) Unwrap() error { return e.cause }

// WithCause returns a copy of e that wraps cause. Like every cause it is for
// logs and errors.Is/As only; callers never see it.
func (e *Error) WithCause(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
}

// MarshalJSON encodes the caller-visible fields.
func (e *Error) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // MarshalJSON returns encoding/json's own error to encoding/json.
	return json.Marshal(struct {
		Code       string `json:"code"`
		Kind       string `json:"kind,omitempty"`
		ID         string `json:"id,omitempty"`
		Field      string `json:"field,omitempty"`
		Message    string `json:"message"`
		Refinement string `json:"refinement,omitempty"`
	}{
		Code:       e.Code.String(),
		Kind:       e.Kind.String(),
		ID:         e.ID,
		Field:      e.Field,
		Message:    e.Message,
		Refinement: e.refinement(),
	})
}

// UnmarshalJSON restores the caller-visible fields of an error, never its cause.
func (e *Error) UnmarshalJSON(data []byte) error {
	var wire struct {
		Code       string `json:"code"`
		Kind       string `json:"kind"`
		ID         string `json:"id"`
		Field      string `json:"field"`
		Message    string `json:"message"`
		Refinement string `json:"refinement"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode resource error: %w", err)
	}
	var decoded Error
	found := false
	for _, code := range append(Codes(), CodeUnspecified) {
		if code.String() == wire.Code {
			decoded.Code = code
			found = true
			break
		}
	}
	if !found {
		return Invalid("code", "unknown resource error code")
	}
	for _, kind := range Kinds() {
		if kind.String() == wire.Kind {
			decoded.Kind = kind
			break
		}
	}
	if wire.Kind != "" && decoded.Kind == KindUnspecified {
		return Invalid("kind", "unknown resource error kind")
	}
	decoded.ID, decoded.Field, decoded.Message = wire.ID, wire.Field, wire.Message
	switch wire.Refinement {
	case "":
	case "missing":
		decoded.invalid = invalidMissing
	case "combination":
		decoded.invalid = invalidCombination
	case "unsupported":
		decoded.invalid = invalidUnsupported
	case "tagLimit":
		decoded.invalid = invalidTagLimit
	case "taggedID":
		decoded.invalid = invalidTaggedID
	case "attachmentLimit":
		decoded.invalid = invalidAttachmentLimit
	case "owned":
		decoded.owned = true
	case "duplicate":
		decoded.duplicate = true
	case "permissionMissing":
		decoded.permissionMissing = true
	case "rulesLimit":
		decoded.rulesLimit = true
	case "deleting":
		decoded.deleting = true
	default:
		return Invalid("refinement", "unknown resource error refinement")
	}
	*e = decoded
	return nil
}

func (e *Error) refinement() string {
	switch e.invalid {
	case invalidMissing:
		return "missing"
	case invalidCombination:
		return "combination"
	case invalidUnsupported:
		return "unsupported"
	case invalidTagLimit:
		return "tagLimit"
	case invalidTaggedID:
		return "taggedID"
	case invalidAttachmentLimit:
		return "attachmentLimit"
	case invalidValue:
	}
	switch {
	case e.owned:
		return "owned"
	case e.duplicate:
		return "duplicate"
	case e.permissionMissing:
		return "permissionMissing"
	case e.rulesLimit:
		return "rulesLimit"
	case e.deleting:
		return "deleting"
	default:
		return ""
	}
}

// CodeOf returns the Code of the first *Error in err's chain.
// A non-nil error that is not an *Error is CodeInternal. Nil is CodeUnspecified.
func CodeOf(err error) Code {
	if err == nil {
		return CodeUnspecified
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// AsError returns err as an *Error, wrapping anything else as CodeInternal.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

// Invalid reports a bad field.
func Invalid(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message}
}

// MissingParameter reports a parameter the request must carry. EC2 answers
// MissingParameter.
func MissingParameter(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message, invalid: invalidMissing}
}

// InvalidCombination reports a parameter that is valid alone but not with
// the rest of the request. EC2 answers InvalidParameterCombination.
func InvalidCombination(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message, invalid: invalidCombination}
}

// Unsupported reports a valid AWS parameter that VWS cannot honor. EC2
// answers UnsupportedOperation, so the request is refused instead of the
// parameter being dropped.
func Unsupported(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message, invalid: invalidUnsupported}
}

// TagLimitExceeded reports tags that are within the EC2 limits but do not
// fit in what the backend stores for one resource. EC2 answers
// TagLimitExceeded, and message says what does not fit.
func TagLimitExceeded(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message, invalid: invalidTagLimit}
}

// IsTagLimitExceeded reports whether e came from TagLimitExceeded.
func IsTagLimitExceeded(e *Error) bool { return e != nil && e.invalid == invalidTagLimit }

// AttachmentLimitExceeded reports a launch that would attach more volumes to
// one instance than it takes. EC2 answers AttachmentLimitExceeded.
func AttachmentLimitExceeded(message string) *Error {
	return &Error{
		Code: CodeInvalidArgument, Field: "blockDeviceMapping", Message: message, invalid: invalidAttachmentLimit,
	}
}

// IsAttachmentLimitExceeded reports whether e came from AttachmentLimitExceeded.
func IsAttachmentLimitExceeded(e *Error) bool { return e != nil && e.invalid == invalidAttachmentLimit }

// InvalidVpcRange reports a VPC CIDR block EC2 refuses, one with a prefix
// outside /16 to /28. EC2 answers InvalidVpcRange.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func InvalidVpcRange() *Error {
	return &Error{
		Code: CodeInvalidArgument, Kind: KindVpc, Field: "cidrBlock",
		Message: "The CIDR block range is not valid. The block range must be between a /28 netmask and /16 netmask.",
		invalid: invalidVpcRange,
	}
}

// IsInvalidVpcRange reports whether e came from InvalidVpcRange.
func IsInvalidVpcRange(e *Error) bool { return e != nil && e.invalid == invalidVpcRange }

// IsMissingParameter reports whether e came from MissingParameter.
func IsMissingParameter(e *Error) bool { return e != nil && e.invalid == invalidMissing }

// IsInvalidCombination reports whether e came from InvalidCombination.
func IsInvalidCombination(e *Error) bool { return e != nil && e.invalid == invalidCombination }

// IsUnsupported reports whether e came from Unsupported.
func IsUnsupported(e *Error) bool { return e != nil && e.invalid == invalidUnsupported }

// InvalidTaggedID reports a resource ID a tagging call cannot read. EC2
// answers InvalidID, whatever kind the ID names, in its own sentence (#438).
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func InvalidTaggedID(id string) *Error {
	return &Error{
		Code:    CodeInvalidArgument,
		Field:   "ResourceId",
		ID:      id,
		Message: "The ID '" + id + "' is not valid",
		invalid: invalidTaggedID,
	}
}

// IsInvalidTaggedID reports whether e came from InvalidTaggedID.
func IsInvalidTaggedID(e *Error) bool { return e != nil && e.invalid == invalidTaggedID }

// Malformed reports an identifier that failed validation. EC2 names a
// malformed instance ID in its own sentence.
func Malformed(kind Kind, id string) *Error {
	message := "malformed identifier"
	if kind == KindInstance {
		message = "The instance ID '" + id + "' is malformed."
	}
	return &Error{Code: CodeInvalidArgument, Kind: kind, ID: id, Message: message}
}

// NotFound reports a missing resource. Callers in another account get the same code.
// The message is AWS's sentence for the kind, which names the id where AWS does
// (#212, #243).
func NotFound(kind Kind, id string) *Error {
	return &Error{Code: CodeNotFound, Kind: kind, ID: id, Message: notFoundMessage(kind, id)}
}

// notFoundMessage is the text AWS sends for a missing resource. The ids are
// part of the text.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
func notFoundMessage(kind Kind, id string) string {
	switch kind {
	case KindInstance:
		return "The instance ID '" + id + "' does not exist"
	case KindImage:
		return imageNotFoundMessage(id)
	case KindBucket:
		return "The specified bucket does not exist"
	case KindVpc:
		return "The vpc ID '" + id + "' does not exist"
	case KindSubnet:
		return "The subnet ID '" + id + "' does not exist"
	case KindVolume:
		return "The volume '" + id + "' does not exist."
	case KindSecurityGroup:
		return "The security group '" + id + "' does not exist"
	case KindKeyPair:
		return "The key pair '" + id + "' does not exist"
	case KindAddress:
		return "The allocation ID '" + id + "' does not exist"
	case KindSnapshot:
		return "The snapshot '" + id + "' does not exist."
	case KindReservation, KindObject, KindOperation, KindUnspecified:
		return "not found"
	}
	// Exhaustive requires every kind as a case; Go requires this return.
	return "not found"
}

// AlreadyExists reports a resource the caller cannot create again.
func AlreadyExists(kind Kind, id string) *Error {
	return &Error{Code: CodeAlreadyExists, Kind: kind, ID: id, Message: "already exists"}
}

// DuplicatePermission reports a security group rule that is already present.
// The message is EC2's own, from the errors page of the API Reference.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func DuplicatePermission(id string) *Error {
	return &Error{
		Code:      CodeAlreadyExists,
		Kind:      KindSecurityGroup,
		ID:        id,
		Message:   "The specified inbound or outbound rule already exists for that security group.",
		duplicate: true,
	}
}

// IsDuplicatePermission reports whether err is a duplicate security group rule.
func IsDuplicatePermission(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.duplicate
}

// RulesPerSecurityGroupLimitExceeded reports an authorize that would leave a
// group with more than MaxIngressRules inbound rules. The message is the one
// EC2 sends, as quoted in
// https://repost.aws/questions/QUu4w_UD2JRPGnJ4MvWOKeZA
func RulesPerSecurityGroupLimitExceeded(id string) *Error {
	return &Error{
		Code:       CodeResourceExhausted,
		Kind:       KindSecurityGroup,
		ID:         id,
		Message:    "The maximum number of rules per security group has been reached.",
		rulesLimit: true,
	}
}

// IsRulesPerSecurityGroupLimitExceeded reports whether err came from
// RulesPerSecurityGroupLimitExceeded.
func IsRulesPerSecurityGroupLimitExceeded(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.rulesLimit
}

// PermissionNotFound reports a security group rule that is not present.
// The message is EC2's own, from the errors page of the API Reference.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func PermissionNotFound(id string) *Error {
	return &Error{
		Code:              CodeNotFound,
		Kind:              KindSecurityGroup,
		ID:                id,
		Message:           "The specified rule does not exist in this security group.",
		permissionMissing: true,
	}
}

// IsPermissionNotFound reports whether err is a missing security group rule.
func IsPermissionNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.permissionMissing
}

// BucketOwnedMessage is the text S3 sends with BucketAlreadyOwnedByYou, from
// the List of Error Codes in the S3 API Reference PDF (API Version
// 2006-03-01). The current ErrorResponses page describes the code in other
// words.
const BucketOwnedMessage = "Your previous request to create the named bucket succeeded and you already own it."

// BucketAlreadyOwned reports a bucket create for a name the caller already
// owns. It is CodeAlreadyExists, and OwnedByCaller tells it apart from a
// name another account holds (#315).
func BucketAlreadyOwned(name string) *Error {
	return &Error{Code: CodeAlreadyExists, Kind: KindBucket, ID: name, Message: BucketOwnedMessage, owned: true}
}

// OwnedByCaller reports whether err is a BucketAlreadyOwned error.
func OwnedByCaller(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.owned
}

// BucketDeletingMessage is the text S3 sends with OperationAborted, from the
// List of Error Codes in the S3 API Reference PDF (API Version 2006-03-01).
const BucketDeletingMessage = "A conflicting conditional action is currently in progress " +
	"against this resource. Try again."

// BucketDeleting reports a bucket create for a name the caller's own bucket
// still holds while vws-storage deletes it. S3 answers 409 OperationAborted:
// the name is neither another account's (BucketAlreadyExists) nor a bucket
// the caller can use (BucketAlreadyOwnedByYou), and a retry after the delete
// finishes can succeed (#321).
func BucketDeleting(name string) *Error {
	return &Error{Code: CodeConflict, Kind: KindBucket, ID: name, Message: BucketDeletingMessage, deleting: true}
}

// IsBucketDeleting reports whether err is a BucketDeleting error.
func IsBucketDeleting(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.deleting
}

// Conflict reports a lifecycle or occupancy conflict.
func Conflict(kind Kind, id, message string) *Error {
	return &Error{Code: CodeConflict, Kind: kind, ID: id, Message: message}
}

// IdempotencyMismatch reports a client token reused with different parameters.
// The text is EC2's own, from the errors page of the API Reference.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func IdempotencyMismatch() *Error {
	return &Error{
		Code:    CodeIdempotencyMismatch,
		Message: "Arguments on this idempotent request are inconsistent with arguments used in previous request(s).",
	}
}

// Unauthenticated reports a missing or rejected credential.
func Unauthenticated(message string) *Error {
	return &Error{Code: CodeUnauthenticated, Message: message}
}

// Denied reports a caller that is authenticated but not allowed.
func Denied(message string) *Error {
	return &Error{Code: CodePermissionDenied, Message: message}
}

// RequestLimitExceeded reports a request over its account's rate for the
// action. The message is the one EC2 sends with RequestLimitExceeded.
func RequestLimitExceeded() *Error {
	return &Error{Code: CodeResourceExhausted, Message: "Request limit exceeded."}
}

// LaunchLimitExceeded reports a RunInstances that found no room among the
// launches this process lets run at once, after the wait. A retry can
// succeed, and the backend saw nothing.
func LaunchLimitExceeded() *Error {
	return &Error{Code: CodeResourceExhausted, Message: "Too many instance launches in flight; retry later."}
}

// TooLarge reports a body or object that exceeds the size this process accepts.
// It is not a quota, so callers must not retry it unchanged.
func TooLarge(message string) *Error {
	return &Error{Code: CodePayloadTooLarge, Message: message}
}

// Unimplemented reports a path the skeleton does not serve.
func Unimplemented(message string) *Error {
	return &Error{Code: CodeUnimplemented, Message: message}
}

// Internal wraps an unexpected failure. The cause is not shown to callers.
func Internal(err error) *Error {
	return &Error{Code: CodeInternal, Message: "internal error", cause: err}
}
