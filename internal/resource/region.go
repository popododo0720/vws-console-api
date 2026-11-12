package resource

// RegionSummary is the public discovery summary of one registered region.
type RegionSummary struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	State string `json:"state"`
}
