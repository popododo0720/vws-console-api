package resource

import "time"

// RegionStatus is a live observation of the region, never a stored record.
type RegionStatus struct {
	Quorate   bool               `json:"quorate"`
	Leader    *string            `json:"leader"`
	Nodes     []RegionNode       `json:"nodes"`
	LastError *RegionStatusError `json:"lastError"`
}

// RegionNode describes a node's current availability.
type RegionNode struct {
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

// RegionStatusError is the most recent failed status read.
type RegionStatusError struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}
