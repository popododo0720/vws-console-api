package iam

import (
	"sort"
	"time"
)

// MFADeviceAssignment is the AssignmentStatus filter of
// ListVirtualMFADevices.
type MFADeviceAssignment string

// The AWS AssignmentStatus values. Any is the default.
const (
	MFADeviceAssignmentAny        MFADeviceAssignment = "Any"
	MFADeviceAssignmentAssigned   MFADeviceAssignment = "Assigned"
	MFADeviceAssignmentUnassigned MFADeviceAssignment = "Unassigned"
)

// The AWS paging limits of ListVirtualMFADevices.
const (
	DefaultMFADevicePageSize = 100
	MaxMFADevicePageSize     = 1000
)

// VirtualMFADevice is one row of ListVirtualMFADevices. User is set only when
// the device is enabled for that user.
type VirtualMFADevice struct {
	SerialNumber string
	User         *User
	EnableDate   time.Time
}

// VirtualMFADevicePage is one page of ListVirtualMFADevices. Marker is the
// value the next call sends as Marker; it is empty on the last page.
type VirtualMFADevicePage struct {
	Devices     []VirtualMFADevice
	IsTruncated bool
	Marker      string
}

// Matches reports whether a device with this assignment belongs in the
// filter's result. An unknown value matches every device.
func (a MFADeviceAssignment) Matches(assigned bool) bool {
	switch a {
	case MFADeviceAssignmentAssigned:
		return assigned
	case MFADeviceAssignmentUnassigned:
		return !assigned
	case MFADeviceAssignmentAny:
		return true
	default:
		return true
	}
}

// PageVirtualMFADevices filters by assignment status, sorts by serial number
// and returns the AWS page. vws-iam pages devices before the caller can filter
// them, so a caller that needs exact AWS paging collects every device first.
func PageVirtualMFADevices(
	devices []VirtualMFADevice, assignment MFADeviceAssignment, marker string, maxItems int,
) VirtualMFADevicePage {
	if maxItems <= 0 {
		maxItems = DefaultMFADevicePageSize
	}
	if maxItems > MaxMFADevicePageSize {
		maxItems = MaxMFADevicePageSize
	}
	out := make([]VirtualMFADevice, 0, len(devices))
	for _, d := range devices {
		if assignment.Matches(d.User != nil) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SerialNumber < out[j].SerialNumber })
	start := 0
	if marker != "" {
		start = sort.Search(len(out), func(i int) bool { return out[i].SerialNumber > marker })
	}
	end := min(start+maxItems, len(out))
	page := VirtualMFADevicePage{Devices: out[start:end]}
	if end < len(out) {
		page.IsTruncated = true
		page.Marker = out[end-1].SerialNumber
	}
	return page
}
