package resource

import "slices"

// TagVpcsRequest adds or overwrites tags on VPCs. Other tags stay.
type TagVpcsRequest struct {
	IDs  []VpcID           `json:"vpcIds"`
	Tags map[string]string `json:"tags"`
}

// Action returns CreateTags.
func (TagVpcsRequest) Action() Action { return ActionCreateTags }

// Normalize checks the ids and the tags. The direct VPC takes no tag.
func (r TagVpcsRequest) Normalize() (TagVpcsRequest, error) {
	if err := distinctIDs("vpcIds", r.IDs); err != nil {
		return TagVpcsRequest{}, err
	}
	if slices.ContainsFunc(r.IDs, IsDirectVpc) {
		return TagVpcsRequest{}, DirectReadOnly()
	}
	if err := requiredTags(r.Tags); err != nil {
		return TagVpcsRequest{}, err
	}
	return r, nil
}

// TagSubnetsRequest adds or overwrites tags on subnets. Other tags stay.
type TagSubnetsRequest struct {
	IDs  []SubnetID        `json:"subnetIds"`
	Tags map[string]string `json:"tags"`
}

// Action returns CreateTags.
func (TagSubnetsRequest) Action() Action { return ActionCreateTags }

// Normalize checks the ids and the tags. A direct subnet takes no tag, and
// one in the batch refuses the whole batch.
func (r TagSubnetsRequest) Normalize() (TagSubnetsRequest, error) {
	if err := distinctIDs("subnetIds", r.IDs); err != nil {
		return TagSubnetsRequest{}, err
	}
	if slices.ContainsFunc(r.IDs, IsDirectSubnet) {
		return TagSubnetsRequest{}, DirectReadOnly()
	}
	if err := requiredTags(r.Tags); err != nil {
		return TagSubnetsRequest{}, err
	}
	return r, nil
}

func requiredTags(tags map[string]string) error {
	if len(tags) == 0 {
		return Invalid("tags", "required")
	}
	return validTags(tags)
}

func distinctIDs[T interface {
	comparable
	IsZero() bool
}](field string, ids []T) error {
	if len(ids) < 1 || len(ids) > 20 {
		return Invalid(field, "must list from 1 to 20 ids")
	}
	seen := map[T]struct{}{}
	for _, id := range ids {
		if id.IsZero() {
			return Invalid(field, "malformed")
		}
		if _, ok := seen[id]; ok {
			return Invalid(field, "duplicate")
		}
		seen[id] = struct{}{}
	}
	return nil
}
