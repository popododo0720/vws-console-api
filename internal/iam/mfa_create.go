package iam

import (
	"encoding/base32"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// MaxVirtualMFADeviceNameLen bounds VirtualMFADeviceName. The AWS API
// reference documents only a minimum of 1; 226 is the longest name whose
// serial number at path "/" (arn:aws:iam::<12 digits>:mfa/<name>) fits the
// AWS SerialNumber maximum of 256, so a longer name could never be addressed
// by EnableMFADevice or DeleteVirtualMFADevice. vws-iam still caps names at
// 64 characters (popododo0720/vws-iam#179) and answers a longer one
// InvalidInput.
const MaxVirtualMFADeviceNameLen = 226

// virtualMFADeviceNameRE is the AWS VirtualMFADeviceName pattern.
var virtualMFADeviceNameRE = regexp.MustCompile(`^[\w+=,.@-]+$`)

// MFADeviceExistsMsg is the AWS EntityAlreadyExists message of
// CreateVirtualMFADevice for a name the account already holds.
const MFADeviceExistsMsg = "MFADevice entity at the same path and name already exists."

// MFADeviceExists is the EntityAlreadyExists of CreateVirtualMFADevice.
func MFADeviceExists() error {
	return &resource.Error{Code: resource.CodeAlreadyExists, Message: MFADeviceExistsMsg}
}

// mfaDeviceTagQuotaMsg is the AWS LimitExceeded message for more than MaxTags
// tags on one virtual MFA device.
const mfaDeviceTagQuotaMsg = "Cannot exceed quota for TagsPerMfaDevice: 50"

// MFADeviceTagsExceeded is the LimitExceeded of a virtual MFA device that
// would hold more than MaxTags tags.
func MFADeviceTagsExceeded() error { return quota(mfaDeviceTagQuotaMsg) }

// CheckMFADeviceTags validates the optional Tags of CreateVirtualMFADevice as
// AWS answers that action: no tags is valid, more than MaxTags is
// LimitExceeded and an invalid tag is InvalidInput.
func CheckMFADeviceTags(tags []Tag) error {
	if len(tags) > MaxTags {
		return MFADeviceTagsExceeded()
	}
	return MFADeviceTagInput(ValidateTags(tags))
}

// MFADeviceTagInput turns a tag validation failure into the InvalidInput that
// CreateVirtualMFADevice documents for a bad tag, keeping its message. Any
// other error, nil included, is returned as it is.
func MFADeviceTagInput(err error) error {
	var e *resource.Error
	if errors.As(err, &e) && e.Code == resource.CodeInvalidArgument {
		return resource.Invalid("Tags", e.Message)
	}
	return err
}

// CheckVirtualMFADeviceName validates VirtualMFADeviceName as AWS does: 1 to
// MaxVirtualMFADeviceNameLen characters of [\w+=,.@-]. The failures are
// ValidationError (the member field is lower case).
func CheckVirtualMFADeviceName(name string) error {
	const field = "virtualMFADeviceName"
	switch n := utf8.RuneCountInString(name); {
	case n < 1:
		return validationError(field, "Member must have length greater than or equal to 1")
	case n > MaxVirtualMFADeviceNameLen:
		return validationError(field, "Member must have length less than or equal to 226")
	case !virtualMFADeviceNameRE.MatchString(name):
		return validationError(field, `Member must satisfy regular expression pattern: [\w+=,.@-]+`)
	}
	return nil
}

// VirtualMFADeviceSerial is the serial number (ARN) of the virtual MFA device
// name on path in account a. path must be normalized.
func VirtualMFADeviceSerial(a resource.AccountID, path, name string) string {
	return iamARN(a, "mfa", path, name)
}

// NewVirtualMFADevice is a virtual MFA device as CreateVirtualMFADevice
// returns it, once. Base32StringSeed and OtpauthURI (which embeds the seed)
// are secrets: they go only into the CreateVirtualMFADevice response body.
// String, GoString and LogValue print the serial number only, so a %v or a
// slog attribute of the value never leaks the seed.
type NewVirtualMFADevice struct {
	SerialNumber     string
	Base32StringSeed string
	OtpauthURI       string
}

// String implements fmt.Stringer without the secrets.
func (d NewVirtualMFADevice) String() string {
	return "NewVirtualMFADevice{SerialNumber:" + d.SerialNumber + " seed:[REDACTED]}"
}

// GoString implements fmt.GoStringer without the secrets.
func (d NewVirtualMFADevice) GoString() string { return d.String() }

// LogValue implements slog.LogValuer without the secrets.
func (d NewVirtualMFADevice) LogValue() slog.Value {
	return slog.GroupValue(slog.String("serial_number", d.SerialNumber), slog.String("seed", "[REDACTED]"))
}

// CheckEnrollment reports whether seed is a non-empty RFC 4648 base32 seed
// and uri an otpauth://totp/ URI that carries exactly that seed. Neither
// value appears in the error.
func CheckEnrollment(seed, uri string) error {
	if seed == "" {
		return resource.Internal(errNoSeed)
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(seed, "=")); err != nil {
		return resource.Internal(errBadSeed)
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != seed {
		return resource.Internal(errBadURI)
	}
	return nil
}

// The faults CheckEnrollment reports. None carries a secret.
const (
	errNoSeed  enrollmentError = "the virtual MFA device has no seed"
	errBadSeed enrollmentError = "the virtual MFA device seed is not base32"
	errBadURI  enrollmentError = "the virtual MFA device otpauth URI does not carry its seed"
)

// enrollmentError is a malformed enrollment from the backend.
type enrollmentError string

func (e enrollmentError) Error() string { return string(e) }
