package resource

// Allocation is the current provisioned capacity, independent of a usage window.
type Allocation struct {
	VCPU        float64 `json:"vcpu"`
	MemoryBytes int64   `json:"memoryBytes"`
	DiskBytes   int64   `json:"diskBytes"`
}
