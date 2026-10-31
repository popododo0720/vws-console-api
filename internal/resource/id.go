package resource

import (
	"encoding"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// kindTag binds an ID type to its kind and syntax. Only this package can
// declare one, so only this package can declare an ID type.
type kindTag interface {
	kind() Kind
	valid(s string) bool
}

type (
	instanceKind      struct{}
	imageKind         struct{}
	reservationKind   struct{}
	subnetKind        struct{}
	bucketKind        struct{}
	vpcKind           struct{}
	volumeKind        struct{}
	securityGroupKind struct{}
	keyPairKind       struct{}
	addressKind       struct{}
	snapshotKind      struct{}
)

func (instanceKind) kind() Kind      { return KindInstance }
func (imageKind) kind() Kind         { return KindImage }
func (reservationKind) kind() Kind   { return KindReservation }
func (subnetKind) kind() Kind        { return KindSubnet }
func (bucketKind) kind() Kind        { return KindBucket }
func (vpcKind) kind() Kind           { return KindVpc }
func (volumeKind) kind() Kind        { return KindVolume }
func (securityGroupKind) kind() Kind { return KindSecurityGroup }
func (keyPairKind) kind() Kind       { return KindKeyPair }
func (addressKind) kind() Kind       { return KindAddress }
func (snapshotKind) kind() Kind      { return KindSnapshot }

func (instanceKind) valid(s string) bool      { return validMinted(KindInstance, s) }
func (imageKind) valid(s string) bool         { return validMinted(KindImage, s) }
func (reservationKind) valid(s string) bool   { return validMinted(KindReservation, s) }
func (subnetKind) valid(s string) bool        { return validMinted(KindSubnet, s) }
func (bucketKind) valid(s string) bool        { return validBucketName(s) }
func (vpcKind) valid(s string) bool           { return validMinted(KindVpc, s) }
func (volumeKind) valid(s string) bool        { return validMinted(KindVolume, s) }
func (securityGroupKind) valid(s string) bool { return validMinted(KindSecurityGroup, s) }
func (keyPairKind) valid(s string) bool       { return validMinted(KindKeyPair, s) }
func (addressKind) valid(s string) bool       { return validMinted(KindAddress, s) }
func (snapshotKind) valid(s string) bool      { return validMinted(KindSnapshot, s) }

// ID identifies one resource of kind K. The same value is the console path
// segment, the EC2 identifier, and the operation target.
//
// A non-zero ID is well formed. There is no conversion from string.
type ID[K kindTag] struct{ v string }

type (
	// InstanceID identifies an instance ("i-" and 8 to 17 hex digits).
	InstanceID = ID[instanceKind]
	// ImageID identifies a machine image ("ami-" and 8 to 17 hex digits).
	ImageID = ID[imageKind]
	// VpcID identifies a VPC ("vpc-" and 8 to 17 hex digits).
	VpcID = ID[vpcKind]
	// VolumeID identifies a block volume ("vol-" and 8 to 17 hex digits).
	VolumeID = ID[volumeKind]
	// SecurityGroupID identifies a security group ("sg-" and 8 to 17 hex digits).
	SecurityGroupID = ID[securityGroupKind]
	// KeyPairID identifies a key pair ("key-" and 8 to 17 hex digits).
	KeyPairID = ID[keyPairKind]
	// AddressID identifies an allocated address ("eipalloc-" and 8 to 17 hex digits).
	AddressID = ID[addressKind]
	// SnapshotID identifies a volume snapshot ("snap-" and 8 to 17 hex digits).
	SnapshotID = ID[snapshotKind]
	// ReservationID groups the instances one RunInstances call launched.
	ReservationID = ID[reservationKind]
	// SubnetID identifies a subnet.
	SubnetID = ID[subnetKind]
	// BucketName is chosen by the caller. It is not minted.
	BucketName = ID[bucketKind]
)

// String returns the identifier as it appears on the wire.
func (id ID[K]) String() string { return id.v }

// IsZero reports whether id is unset.
func (id ID[K]) IsZero() bool { return id.v == "" }

// Kind returns the kind id names.
func (id ID[K]) Kind() Kind {
	var k K
	return k.kind()
}

// Ref returns a kind-erased reference.
func (id ID[K]) Ref() Ref { return Ref{kind: id.Kind(), id: id.v} }

// MarshalText encodes id as its wire form.
func (id ID[K]) MarshalText() ([]byte, error) { return []byte(id.v), nil }

// UnmarshalText parses b. An empty or malformed value is CodeInvalidArgument.
func (id *ID[K]) UnmarshalText(b []byte) error {
	var k K
	s := string(b)
	if !k.valid(s) {
		return Malformed(k.kind(), s)
	}
	id.v = s
	return nil
}

func (id *ID[K]) mint(entropy io.Reader) error {
	var k K
	prefix := k.kind().info().prefix
	if prefix == "" {
		return fmt.Errorf("resource: %v identifiers are chosen by the caller, not minted", k.kind())
	}
	var raw [9]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		return fmt.Errorf("resource: mint %v: %w", k.kind(), err)
	}
	id.v = prefix + hex.EncodeToString(raw[:])[:17]
	return nil
}

func validMinted(k Kind, s string) bool {
	prefix := k.info().prefix
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || len(rest) < 8 || len(rest) > 17 {
		return false
	}
	for _, r := range rest {
		if !isHex(r) {
			return false
		}
	}
	return true
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

func validBucketName(s string) bool {
	if len(s) < 3 || len(s) > 63 || strings.Contains(s, "..") || ipv4Shaped(s) || reservedBucketName(s) {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '.':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// reservedBucketName reports whether s starts with a prefix or ends with a
// suffix reserved by the AWS general purpose bucket naming rules. AWS reserves
// the prefixes xn--, sthree- and amzn-s3-demo- and the suffixes -s3alias,
// --ol-s3, .mrap, --x-s3, --table-s3 and -an. A name ends in -an only for a
// bucket in an account-regional namespace, which this API does not create, so
// the suffix is refused here (#500).
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func reservedBucketName(s string) bool {
	for _, prefix := range [...]string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	for _, suffix := range [...]string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3", "-an"} {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// ipv4Shaped reports whether s is four dot-separated runs of one to three
// digits. S3 refuses that shape so a bucket name never matches an IP address.
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func ipv4Shaped(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) != 4 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 3 {
			return false
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

type textValue[T any] interface {
	*T
	encoding.TextUnmarshaler
}

// Parse turns an untrusted string into a validated model value.
// It is the one way surfaces read identifiers from paths, headers, and forms.
func Parse[T any, PT textValue[T]](s string) (T, error) {
	var v T
	if err := PT(&v).UnmarshalText([]byte(s)); err != nil {
		var zero T
		return zero, err //nolint:wrapcheck // UnmarshalText already returns the caller-facing *Error.
	}
	return v, nil
}

type mintable[T any] interface {
	*T
	mint(entropy io.Reader) error
}

// Mint creates a fresh identifier from entropy. Backends mint. Surfaces do not.
func Mint[T any, PT mintable[T]](entropy io.Reader) (T, error) {
	var v T
	if err := PT(&v).mint(entropy); err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}

// Ref names one resource of any kind. The zero Ref names nothing.
type Ref struct {
	kind Kind
	id   string
}

// Kind returns the referenced kind.
func (r Ref) Kind() Kind { return r.kind }

// ID returns the identifier in wire form.
func (r Ref) ID() string { return r.id }

// IsZero reports whether r names nothing.
func (r Ref) IsZero() bool { return r.kind == KindUnspecified || r.id == "" }

// MarshalJSON encodes kind and id.
func (r Ref) MarshalJSON() ([]byte, error) {
	type wire struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	return marshalJSON(wire{Kind: r.kind.String(), ID: r.id})
}

// UnmarshalJSON parses kind and id, validating the identifier.
func (r *Ref) UnmarshalJSON(b []byte) error {
	var wire struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if err := unmarshalJSON(b, &wire); err != nil {
		return err
	}
	parsed, err := ParseRef(wire.Kind, wire.ID)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParseRef validates id against the wire kind name.
func ParseRef(kind, id string) (Ref, error) {
	var k Kind
	for _, c := range Kinds() {
		if c.String() == kind {
			k = c
			break
		}
	}
	if k == KindUnspecified {
		return Ref{}, Malformed(KindUnspecified, kind)
	}
	if err := validateRefID(k, id); err != nil {
		return Ref{}, err
	}
	return Ref{kind: k, id: id}, nil
}

func validateRefID(k Kind, id string) error {
	var err error
	switch k {
	case KindInstance:
		_, err = Parse[InstanceID](id)
	case KindImage:
		_, err = Parse[ImageID](id)
	case KindReservation:
		_, err = Parse[ReservationID](id)
	case KindSubnet:
		_, err = Parse[SubnetID](id)
	case KindBucket:
		_, err = Parse[BucketName](id)
	case KindObject:
		_, err = Parse[ObjectKey](id)
	case KindOperation:
		_, err = Parse[OperationID](id)
	case KindVpc:
		_, err = Parse[VpcID](id)
	case KindVolume:
		_, err = Parse[VolumeID](id)
	case KindSecurityGroup:
		_, err = Parse[SecurityGroupID](id)
	case KindKeyPair:
		_, err = Parse[KeyPairID](id)
	case KindAddress:
		_, err = Parse[AddressID](id)
	case KindSnapshot:
		_, err = Parse[SnapshotID](id)
	case KindUnspecified:
		err = Malformed(k, id)
	default:
		err = Malformed(k, id)
	}
	return err
}

// hasControl reports whether s contains a space or a non-printable rune.
func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}
