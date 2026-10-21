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
// never appears in a wire body. An empty EC2Code leaves the surface on its
// default map.
type Error struct {
	Code    Code
	Kind    Kind
	ID      string
	Field   string
	Message string
	EC2Code string
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%v: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%v: %s", e.Code, e.Message)
}

// Unwrap returns the internal cause.
func (e *Error) Unwrap() error { return e.cause }

// MarshalJSON encodes the caller-visible fields.
func (e *Error) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // MarshalJSON returns encoding/json's own error to encoding/json.
	return json.Marshal(struct {
		Code    string `json:"code"`
		Kind    string `json:"kind,omitempty"`
		ID      string `json:"id,omitempty"`
		Field   string `json:"field,omitempty"`
		Message string `json:"message"`
		EC2Code string `json:"ec2Code,omitempty"`
	}{
		Code:    e.Code.String(),
		Kind:    e.Kind.String(),
		ID:      e.ID,
		Field:   e.Field,
		Message: e.Message,
		EC2Code: e.EC2Code,
	})
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

// Malformed reports an identifier that failed validation.
func Malformed(kind Kind, id string) *Error {
	return &Error{Code: CodeInvalidArgument, Kind: kind, ID: id, Message: "malformed identifier"}
}

// NotFound reports a missing resource. Callers in another account get the same code.
func NotFound(kind Kind, id string) *Error {
	return &Error{Code: CodeNotFound, Kind: kind, ID: id, Message: "not found"}
}

// AlreadyExists reports a resource the caller cannot create again.
func AlreadyExists(kind Kind, id string) *Error {
	return &Error{Code: CodeAlreadyExists, Kind: kind, ID: id, Message: "already exists"}
}

// Conflict reports a lifecycle or occupancy conflict.
func Conflict(kind Kind, id, message string) *Error {
	return &Error{Code: CodeConflict, Kind: kind, ID: id, Message: message}
}

// IdempotencyMismatch reports a client token reused with different parameters.
func IdempotencyMismatch() *Error {
	return &Error{Code: CodeIdempotencyMismatch, Message: "client token reused with different parameters"}
}

// Unauthenticated reports a missing or rejected credential.
func Unauthenticated(message string) *Error {
	return &Error{Code: CodeUnauthenticated, Message: message}
}

// Denied reports a caller that is authenticated but not allowed.
func Denied(message string) *Error {
	return &Error{Code: CodePermissionDenied, Message: message}
}

// TooLarge reports a body or object that exceeds the size this process accepts.
// It is not a quota, so callers must not retry it unchanged.
func TooLarge(message string) *Error {
	return &Error{Code: CodePayloadTooLarge, Message: message}
}

// EC2 error code strings for AuthorizeSecurityGroupIngress refusals.
const (
	EC2InvalidPermissionDuplicate   = "InvalidPermission.Duplicate"
	EC2InvalidPermissionMalformed   = "InvalidPermission.Malformed"
	EC2UnsupportedOperation         = "UnsupportedOperation"
	EC2InvalidPrefixListIDMalformed = "InvalidPrefixListId.Malformed"
	EC2InvalidParameterValue        = "InvalidParameterValue"
	EC2InvalidGroupNotFound         = "InvalidGroup.NotFound"
	EC2InvalidGroupIDMalformed      = "InvalidGroupId.Malformed"
)

// DuplicatePermission reports a rule the group already has, or a repeated rule in one call.
func DuplicatePermission(id, field string) *Error {
	if field == "" {
		field = "ipPermissions"
	}
	return &Error{
		Code: CodeAlreadyExists, Kind: KindSecurityGroup, ID: id, Field: field,
		Message: "duplicate permission", EC2Code: EC2InvalidPermissionDuplicate,
	}
}

// MissingIngressPorts reports a TCP or UDP permission that omits a port.
// AWS returns InvalidParameterValue for that omission.
func MissingIngressPorts(field string) *Error {
	return &Error{
		Code: CodeInvalidArgument, Field: field, EC2Code: EC2InvalidParameterValue,
		Message: "Invalid value 'Must specify both from and to ports with TCP/UDP.' for portRange.",
	}
}

// MissingICMPPorts reports an ICMP permission that omits a type or a code.
// AWS returns InvalidParameterValue for that omission.
func MissingICMPPorts(field string) *Error {
	return &Error{
		Code: CodeInvalidArgument, Field: field, EC2Code: EC2InvalidParameterValue,
		Message: "Invalid value 'Must specify both from and to ports with ICMP.' for portRange.",
	}
}

// MalformedPermission reports an ingress permission the grammar rejects.
func MalformedPermission(field, message string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: message, EC2Code: EC2InvalidPermissionMalformed}
}

// UnsupportedIngress reports a source this service does not store.
func UnsupportedIngress(field string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: "unsupported", EC2Code: EC2UnsupportedOperation}
}

// MalformedPrefixList reports a prefix list.
func MalformedPrefixList(field string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: "malformed", EC2Code: EC2InvalidPrefixListIDMalformed}
}

// RejectedDescription reports a rule description.
func RejectedDescription(field string) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: "unsupported", EC2Code: EC2InvalidParameterValue}
}

// GroupNotFound reports a missing security group.
func GroupNotFound(id string) *Error {
	return &Error{
		Code: CodeNotFound, Kind: KindSecurityGroup, ID: id, Message: "not found",
		EC2Code: EC2InvalidGroupNotFound,
	}
}

// AsMalformedGroupID copies err and marks it as a malformed security group id.
func AsMalformedGroupID(err error) *Error {
	e := AsError(err)
	out := *e
	out.EC2Code = EC2InvalidGroupIDMalformed
	return &out
}

// Unimplemented reports a path the skeleton does not serve.
func Unimplemented(message string) *Error {
	return &Error{Code: CodeUnimplemented, Message: message}
}

// Internal wraps an unexpected failure. The cause is not shown to callers.
func Internal(err error) *Error {
	return &Error{Code: CodeInternal, Message: "internal error", cause: err}
}
