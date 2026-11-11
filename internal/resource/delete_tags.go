package resource

import (
	"slices"
	"strings"
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

// reservedTagKey reports whether k starts with awsTagPrefix in any case, as
// EC2 reserves it.
func reservedTagKey(k string) bool {
	return strings.HasPrefix(strings.ToLower(k), awsTagPrefix)
}

// ValidateTagSelectors checks DeleteTags selectors before any resource kind is handled.
func ValidateTagSelectors(sel []TagSelector) error {
	if len(sel) > maxTagSelectors {
		return Invalid("tags", "too many")
	}
	for _, s := range sel {
		if err := validTagText(s.Key, "key", 1, 128); err != nil {
			return err
		}
		if reservedTagKey(s.Key) {
			return Invalid("tags", "Value ( "+s.Key+" ) for parameter key is invalid. "+
				"Tag keys starting with 'aws:' are reserved for internal use")
		}
		if s.Value != nil {
			if err := validTagText(*s.Value, "value", 0, 256); err != nil {
				return err
			}
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
			if !reservedTagKey(k) {
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
	if err := ValidateTagSelectors(r.Tags); err != nil {
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
	if err := ValidateTagSelectors(r.Tags); err != nil {
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
	if err := ValidateTagSelectors(r.Tags); err != nil {
		return UntagSubnetsRequest{}, err
	}
	return r, nil
}
