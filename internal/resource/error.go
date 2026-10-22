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

// Unimplemented reports a path the skeleton does not serve.
func Unimplemented(message string) *Error {
	return &Error{Code: CodeUnimplemented, Message: message}
}

// Internal wraps an unexpected failure. The cause is not shown to callers.
func Internal(err error) *Error {
	return &Error{Code: CodeInternal, Message: "internal error", cause: err}
}
