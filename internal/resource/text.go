package resource

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"unicode"
)

// rule marks a validated string type. Only this package declares rules.
type rule interface {
	valid(s string) bool
	kind() Kind
}

type (
	accountRule     struct{}
	clientTokenRule struct{}
	objectKeyRule   struct{}
	regionRule      struct{}
)

func (accountRule) kind() Kind     { return KindUnspecified }
func (clientTokenRule) kind() Kind { return KindUnspecified }
func (objectKeyRule) kind() Kind   { return KindObject }
func (regionRule) kind() Kind      { return KindUnspecified }

func (accountRule) valid(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (clientTokenRule) valid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		ok := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if i == 0 && (r == '_' || r == '-') {
			ok = false
		}
		if !ok {
			return false
		}
	}
	return true
}

func (objectKeyRule) valid(s string) bool {
	if len(s) < 1 || len(s) > 1024 || strings.ContainsRune(s, 0) || strings.HasPrefix(s, "/") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (regionRule) valid(s string) bool { return s == RegionName }

// RegionName is the only region this process routes. Both surfaces use it.
const RegionName = "vws-1"

// ZoneName is the zone recorded on instances this process launches.
const ZoneName = "vws-1a"

// Text is a validated string. A non-zero Text is well formed.
type Text[R rule] struct{ v string }

type (
	// AccountID is the 12-digit owner of a resource.
	AccountID = Text[accountRule]
	// ClientToken is the caller's idempotency key for one mutation.
	ClientToken = Text[clientTokenRule]
	// ObjectKey is the key of an object inside a bucket.
	ObjectKey = Text[objectKeyRule]
	// Region is the region name. Only RegionName is valid.
	Region = Text[regionRule]
)

// String returns the wire form.
func (t Text[R]) String() string { return t.v }

// IsZero reports whether t is unset.
func (t Text[R]) IsZero() bool { return t.v == "" }

// MarshalText encodes t.
func (t Text[R]) MarshalText() ([]byte, error) { return []byte(t.v), nil }

// UnmarshalText parses b.
func (t *Text[R]) UnmarshalText(b []byte) error {
	var rule R
	s := string(b)
	if !rule.valid(s) {
		return Malformed(rule.kind(), s)
	}
	t.v = s
	return nil
}

// NewClientToken draws a token from entropy. crypto/rand is used when
// entropy is nil. Surfaces do not call it. The kernel does, for EC2 actions
// whose wire shape omits ClientToken. RunInstances and CreateSubnet still
// reject a zero token: a token minted inside mutate would make every retry
// a new launch.
func NewClientToken(entropy interface{ Read([]byte) (int, error) }) (ClientToken, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var b [16]byte
	if _, err := entropy.Read(b[:]); err != nil {
		return ClientToken{}, Internal(err)
	}
	return Parse[ClientToken]("t-" + hex.EncodeToString(b[:]))
}
