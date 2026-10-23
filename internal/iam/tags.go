package iam

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// The AWS limits for tags on an IAM resource.
const (
	// MaxTags is the AWS limit of tags per IAM policy.
	MaxTags = 50
	// MaxTagKeyLen is the AWS limit of a tag key, in characters.
	MaxTagKeyLen = 128
	// MaxTagValueLen is the AWS limit of a tag value, in characters.
	MaxTagValueLen = 256
	// DefaultTagPageSize is the AWS default MaxItems of ListPolicyTags.
	DefaultTagPageSize = 100
	// MaxTagPageSize is the AWS maximum MaxItems of ListPolicyTags.
	MaxTagPageSize = 1000
)

// Tag is one AWS IAM tag.
type Tag struct {
	Key   string
	Value string
}

// TagPage is one page of ListPolicyTags. Marker is the value the next call
// sends as Marker; it is empty on the last page.
type TagPage struct {
	Tags        []Tag
	IsTruncated bool
	Marker      string
}

// tagAlphabet is the AWS tag character class: letters, separators, numbers
// and _ . : / = + - @.
const tagAlphabet = `[\p{L}\p{Z}\p{N}_.:/=+\-@]`

const (
	tagKeyPattern   = tagAlphabet + "+"
	tagValuePattern = tagAlphabet + "*"
)

var (
	tagKeyRE   = regexp.MustCompile("^" + tagKeyPattern + "$")
	tagValueRE = regexp.MustCompile("^" + tagValuePattern + "$")
)

// reservedTagPrefix is the tag key and value prefix AWS reserves.
const reservedTagPrefix = "aws:"

// ValidateTag reports an invalid tag outside a request. The AWS Query surface
// calls ValidateTagAt with the tag's member index instead.
func ValidateTag(tag Tag) error { return validateTag(tag, "tags.member") }

// ValidateTagAt reports an invalid tag at the one-based index of the request's
// Tags list. A length or pattern failure is AWS ValidationError; a reserved
// key prefix is InvalidInput.
func ValidateTagAt(tag Tag, index int) error {
	return validateTag(tag, "tags."+strconv.Itoa(index)+".member")
}

func validateTag(tag Tag, member string) error {
	if err := validateTagKey(tag.Key, member+".key"); err != nil {
		return err
	}
	return validateTagValue(tag.Value, member+".value")
}

// ValidateTags reports the first invalid tag of tags.
func ValidateTags(tags []Tag) error {
	for _, tag := range tags {
		if err := ValidateTag(tag); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTagKey reports an invalid tag key outside a request.
func ValidateTagKey(key string) error { return validateTagKey(key, "tagKeys.member") }

// ValidateTagKeyAt reports an invalid tag key at the one-based index of the
// request's TagKeys list.
func ValidateTagKeyAt(key string, index int) error {
	return validateTagKey(key, "tagKeys."+strconv.Itoa(index)+".member")
}

func validateTagKey(key, member string) error {
	if n := utf8.RuneCountInString(key); n < 1 {
		return validationError(member, "Member must have length greater than or equal to 1")
	} else if n > MaxTagKeyLen {
		return validationError(member, "Member must have length less than or equal to "+strconv.Itoa(MaxTagKeyLen))
	}
	if !tagKeyRE.MatchString(key) {
		return validationError(member, "Member must satisfy regular expression pattern: "+tagKeyPattern)
	}
	if strings.HasPrefix(strings.ToLower(key), reservedTagPrefix) {
		return resource.Invalid("TagKey", "the tag key "+strconv.Quote(key)+" begins with the reserved prefix aws:")
	}
	return nil
}

func validateTagValue(value, member string) error {
	if n := utf8.RuneCountInString(value); n > MaxTagValueLen {
		return validationError(member, "Member must have length less than or equal to "+strconv.Itoa(MaxTagValueLen))
	}
	if !tagValueRE.MatchString(value) {
		return validationError(member, "Member must satisfy regular expression pattern: "+tagValuePattern)
	}
	if strings.HasPrefix(strings.ToLower(value), reservedTagPrefix) {
		return resource.Invalid("TagValue", "the tag value "+strconv.Quote(value)+" begins with the reserved prefix aws:")
	}
	return nil
}

// validationError is the AWS Query failure for a request member constraint.
func validationError(field, constraint string) error {
	return resource.Invalid(field, "1 validation error detected: Value at '"+field+
		"' failed to satisfy constraint: "+constraint)
}
