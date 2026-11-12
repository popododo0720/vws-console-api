package resource

// Regional identifies the origin of an inventory item, including merged lists.
type Regional struct {
	Region string `json:"region,omitempty"`
}

// SetRegion records the region that served the item.
func (r *Regional) SetRegion(region string) { r.Region = region }

// DefaultRegion supplies an origin for backends that serve one inventory.
func (r *Regional) DefaultRegion(region string) {
	if r.Region != "" {
		return
	}
	if region == "" || region == "all" {
		region = RegionName
	}
	r.Region = region
}
