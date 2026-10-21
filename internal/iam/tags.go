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

var (
	tagKeyRE   = regexp.MustCompile("^" + tagAlphabet + "+$")
	tagValueRE = regexp.MustCompile("^" + tagAlphabet + "*$")
)

// reservedTagPrefix is the tag key and value prefix AWS reserves.
const reservedTagPrefix = "aws:"

// ValidateTag reports an invalid tag as AWS InvalidInput.
func ValidateTag(tag Tag) error {
	if n := utf8.RuneCountInString(tag.Key); n < 1 || n > MaxTagKeyLen {
		return resource.Invalid("TagKey", "the tag key must be 1 to "+strconv.Itoa(MaxTagKeyLen)+" characters")
	}
	if !tagKeyRE.MatchString(tag.Key) {
		return resource.Invalid("TagKey", "the tag key "+strconv.Quote(tag.Key)+
			" has a character outside the allowed alphabet")
	}
	if strings.HasPrefix(strings.ToLower(tag.Key), reservedTagPrefix) {
		return resource.Invalid("TagKey", "the tag key "+strconv.Quote(tag.Key)+" begins with the reserved prefix aws:")
	}
	if n := utf8.RuneCountInString(tag.Value); n > MaxTagValueLen {
		return resource.Invalid("TagValue", "the tag value must be at most "+strconv.Itoa(MaxTagValueLen)+" characters")
	}
	if !tagValueRE.MatchString(tag.Value) {
		return resource.Invalid("TagValue", "the tag value "+strconv.Quote(tag.Value)+
			" has a character outside the allowed alphabet")
	}
	if strings.HasPrefix(strings.ToLower(tag.Value), reservedTagPrefix) {
		return resource.Invalid("TagValue", "the tag value "+strconv.Quote(tag.Value)+" begins with the reserved prefix aws:")
	}
	return nil
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

// ValidateTagKey reports an invalid tag key as AWS InvalidInput.
func ValidateTagKey(key string) error {
	return ValidateTag(Tag{Key: key})
}

// validationError is the AWS Query failure for a request member constraint.
func validationError(field, constraint string) error {
	return resource.Invalid(field, "1 validation error detected: Value at '"+field+
		"' failed to satisfy constraint: "+constraint)
}
