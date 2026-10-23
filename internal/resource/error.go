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
}

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
		Code    string `json:"code"`
		Kind    string `json:"kind,omitempty"`
		ID      string `json:"id,omitempty"`
		Field   string `json:"field,omitempty"`
		Message string `json:"message"`
	}{
		Code:    e.Code.String(),
		Kind:    e.Kind.String(),
		ID:      e.ID,
		Field:   e.Field,
		Message: e.Message,
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
// EC2 names a missing volume in its own sentence (#212, #243).
func NotFound(kind Kind, id string) *Error {
	message := "not found"
	if kind == KindVolume {
		message = "The volume '" + id + "' does not exist."
	}
	return &Error{Code: CodeNotFound, Kind: kind, ID: id, Message: message}
}

// AlreadyExists reports a resource the caller cannot create again.
func AlreadyExists(kind Kind, id string) *Error {
	return &Error{Code: CodeAlreadyExists, Kind: kind, ID: id, Message: "already exists"}
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
