package resource

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// TagSelector names a tag to delete. With no Value it matches the key
// whatever its value; with a Value, the empty string included, it matches
// only that value, as in EC2 DeleteTags.
type TagSelector struct {
	Key   string  `json:"key"`
	Value *string `json:"value,omitempty"`
}

// maxTagSelectors bounds the selectors of one DeleteTags. It is MaxTags, the
// Tag.N bound EC2 Query reads for CreateTags and DeleteTags, so the console
// and EC2 Query take the same requests.
const maxTagSelectors = MaxTags

// awsTagPrefix marks tags EC2 reserves for itself. DeleteTags never removes
// them and a caller may not name them.
const awsTagPrefix = "aws:"

func validSelectors(sel []TagSelector) error {
	if len(sel) > maxTagSelectors {
		return Invalid("tags", "too many")
	}
	for _, s := range sel {
		if n := utf8.RuneCountInString(s.Key); n < 1 || n > 128 || !tagText(s.Key) {
			return Invalid("tags", "malformed key")
		}
		if strings.HasPrefix(s.Key, awsTagPrefix) {
			return Invalid("tags", "tag keys starting with 'aws:' are reserved")
		}
		if s.Value != nil && (utf8.RuneCountInString(*s.Value) > 256 || !tagText(*s.Value)) {
			return Invalid("tags", "malformed value")
		}
	}
	return nil
}

// RemoveTags returns base without the tags sel matches. An empty sel removes
// every tag except the aws: ones. A selector that matches nothing is not an
// error, so a repeated delete has the same result.
func RemoveTags(base map[string]string, sel []TagSelector) map[string]string {
	out := make(map[string]string, len(base))
	for k, v := range base {
		out[k] = v
	}
	if len(sel) == 0 {
		for k := range out {
			if !strings.HasPrefix(k, awsTagPrefix) {
				delete(out, k)
			}
		}
		return out
	}
	for _, s := range sel {
		v, ok := out[s.Key]
		if ok && (s.Value == nil || *s.Value == v) {
			delete(out, s.Key)
		}
	}
	return out
}

// DeleteTagsRequest deletes tags from instances.
type DeleteTagsRequest struct {
	IDs  []InstanceID  `json:"instanceIds"`
	Tags []TagSelector `json:"tags,omitempty"`
}

// Action returns DeleteTags.
func (DeleteTagsRequest) Action() Action { return ActionDeleteTags }

// Normalize checks the ids and the selectors.
func (r DeleteTagsRequest) Normalize() (DeleteTagsRequest, error) {
	if err := instanceIDs(r.IDs); err != nil {
		return DeleteTagsRequest{}, err
	}
	if err := validSelectors(r.Tags); err != nil {
		return DeleteTagsRequest{}, err
	}
	return r, nil
}

// UntagVpcsRequest deletes tags from VPCs.
type UntagVpcsRequest struct {
	IDs  []VpcID       `json:"vpcIds"`
	Tags []TagSelector `json:"tags,omitempty"`
}

// Action returns DeleteTags.
func (UntagVpcsRequest) Action() Action { return ActionDeleteTags }

// Normalize checks the ids and the selectors.
func (r UntagVpcsRequest) Normalize() (UntagVpcsRequest, error) {
	if err := distinctIDs("vpcIds", r.IDs); err != nil {
		return UntagVpcsRequest{}, err
	}
	if slices.ContainsFunc(r.IDs, IsDirectVpc) {
		return UntagVpcsRequest{}, DirectReadOnly()
	}
	if err := validSelectors(r.Tags); err != nil {
		return UntagVpcsRequest{}, err
	}
	return r, nil
}

// UntagSubnetsRequest deletes tags from subnets.
type UntagSubnetsRequest struct {
	IDs  []SubnetID    `json:"subnetIds"`
	Tags []TagSelector `json:"tags,omitempty"`
}

// Action returns DeleteTags.
func (UntagSubnetsRequest) Action() Action { return ActionDeleteTags }

// Normalize checks the ids and the selectors.
func (r UntagSubnetsRequest) Normalize() (UntagSubnetsRequest, error) {
	if err := distinctIDs("subnetIds", r.IDs); err != nil {
		return UntagSubnetsRequest{}, err
	}
	if slices.ContainsFunc(r.IDs, IsDirectSubnet) {
		return UntagSubnetsRequest{}, DirectReadOnly()
	}
	if err := validSelectors(r.Tags); err != nil {
		return UntagSubnetsRequest{}, err
	}
	return r, nil
}
