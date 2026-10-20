package iamquery

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// tagMemberRE matches one indexed member of the Tags list, as the AWS Query
// protocol encodes it.
var tagMemberRE = regexp.MustCompile(`^Tags\.member\.([1-9][0-9]*)\.(Key|Value)$`)

// tagKeyMemberRE matches one indexed member of TagKeys.
var tagKeyMemberRE = regexp.MustCompile(`^TagKeys\.member\.([1-9][0-9]*)$`)

// tagXML is the AWS Tag structure.
type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// tagsResult is the ListPolicyTags result.
type tagsResult struct {
	IsTruncated bool     `xml:"IsTruncated"`
	Marker      string   `xml:"Marker,omitempty"`
	Tags        []tagXML `xml:"Tags>member"`
}

// nullMember is the AWS Query failure for a missing list member.
func nullMember(field string) error {
	return resource.Invalid(field, "1 validation error detected: Value null at '"+field+
		"' failed to satisfy constraint: Member must not be null")
}

// badMember is the AWS Query failure for a member constraint.
func badMember(field, constraint string) error {
	return resource.Invalid(field, "1 validation error detected: Value at '"+field+
		"' failed to satisfy constraint: "+constraint)
}

// requirePolicyArn checks PolicyArn (required, 20 to 2048 characters) and
// applies the AWS rule that tagging or untagging also needs permission to
// list tags.
func requirePolicyArn(c *exchange, h *handler, action string) error {
	arn := c.form("PolicyArn")
	if arn == "" {
		return nullMember("policyArn")
	}
	if n := len(arn); n < 20 || n > 2048 {
		return resource.Invalid("policyArn", "1 validation error detected: Value '"+arn+
			"' at 'policyArn' failed to satisfy constraint: Member must have length between 20 and 2048")
	}
	if action == "iam:TagPolicy" || action == "iam:UntagPolicy" {
		if err := iam.Check(c.r.Context(), h.cfg.Authorizer, c.caller, "iam:ListPolicyTags", arn); err != nil {
			return err
		}
	}
	return nil
}

// parseTagMembers reads Tags.member.N.Key/Value into request order.
func parseTagMembers(c *exchange) ([]iam.Tag, error) {
	byIndex := map[int]*iam.Tag{}
	for key := range c.r.Form {
		if !strings.HasPrefix(key, "Tags.member.") {
			continue
		}
		m := tagMemberRE.FindStringSubmatch(key)
		if m == nil {
			return nil, resource.Invalid("tags", "Parameter "+key+" is not supported")
		}
		index, err := strconv.Atoi(m[1])
		if err != nil || index > iam.MaxTags {
			return nil, badMember("tags", "Member must have length less than or equal to 50")
		}
		if byIndex[index] == nil {
			byIndex[index] = &iam.Tag{}
		}
		if m[2] == "Key" {
			byIndex[index].Key = c.form(key)
		} else {
			byIndex[index].Value = c.form(key)
		}
	}
	indexes := make([]int, 0, len(byIndex))
	for index := range byIndex {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	tags := make([]iam.Tag, 0, len(indexes))
	for _, index := range indexes {
		tags = append(tags, *byIndex[index])
	}
	switch {
	case len(tags) == 0:
		return nil, nullMember("tags")
	case len(tags) > iam.MaxTags:
		return nil, badMember("tags", "Member must have length less than or equal to 50")
	}
	return tags, nil
}

// parseTagKeys reads TagKeys.member.N into request order.
func parseTagKeys(c *exchange) ([]string, error) {
	byIndex := map[int]string{}
	for key := range c.r.Form {
		if !strings.HasPrefix(key, "TagKeys.member.") {
			continue
		}
		m := tagKeyMemberRE.FindStringSubmatch(key)
		if m == nil {
			return nil, resource.Invalid("tagKeys", "Parameter "+key+" is not supported")
		}
		index, err := strconv.Atoi(m[1])
		if err != nil || index > iam.MaxTags {
			return nil, badMember("tagKeys", "Member must have length less than or equal to 50")
		}
		byIndex[index] = c.form(key)
	}
	indexes := make([]int, 0, len(byIndex))
	for index := range byIndex {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	keys := make([]string, 0, len(indexes))
	for _, index := range indexes {
		keys = append(keys, byIndex[index])
	}
	switch {
	case len(keys) == 0:
		return nil, nullMember("tagKeys")
	case len(keys) > iam.MaxTags:
		return nil, badMember("tagKeys", "Member must have length less than or equal to 50")
	}
	for _, key := range keys {
		if key == "" {
			return nil, badMember("tagKeys", "Member must have length greater than or equal to 1")
		}
	}
	return keys, nil
}

// maxItemsParam reads MaxItems; zero means the AWS default of 100.
func maxItemsParam(c *exchange) (int, error) {
	raw := c.form("MaxItems")
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > iam.MaxTagPageSize {
		return 0, resource.Invalid("maxItems", "1 validation error detected: Value '"+raw+
			"' at 'maxItems' failed to satisfy constraint: Member must have value between 1 and 1000")
	}
	return n, nil
}

// markerParam checks ListPolicyTags Marker: 1 or more characters in the
// AWS range U+0020 to U+00FF.
func markerParam(c *exchange) error {
	marker := c.form("Marker")
	if marker == "" {
		return nil
	}
	for _, r := range marker {
		if r < 0x20 || r > 0xFF {
			return resource.Invalid("Marker", "The Marker value is invalid.")
		}
	}
	return nil
}
