package iamquery

import (
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// virtualMFADeviceXML is the AWS VirtualMFADevice structure. User is set only
// when the device is enabled for a user.
type virtualMFADeviceXML struct {
	SerialNumber string   `xml:"SerialNumber"`
	User         *userXML `xml:"User,omitempty"`
	EnableDate   string   `xml:"EnableDate,omitempty"`
}

// virtualMFADevicesResult is the ListVirtualMFADevices result.
type virtualMFADevicesResult struct {
	VirtualMFADevices []virtualMFADeviceXML `xml:"VirtualMFADevices>member"`
	IsTruncated       bool                  `xml:"IsTruncated"`
	Marker            string                `xml:"Marker,omitempty"`
}

func toVirtualMFADevice(d iam.VirtualMFADevice) virtualMFADeviceXML {
	out := virtualMFADeviceXML{SerialNumber: d.SerialNumber}
	if d.User != nil {
		u := toUser(*d.User)
		out.User = &u
	}
	if !d.EnableDate.IsZero() {
		out.EnableDate = stamp(d.EnableDate)
	}
	return out
}

// mfaDeviceMarkerParam checks the ListVirtualMFADevices Marker. AWS gives it a
// minimum length of 1 and the same character range as the other list markers.
func mfaDeviceMarkerParam(c *exchange) error {
	if c.r.Form.Has("Marker") && c.form("Marker") == "" {
		return resource.Invalid("Marker", "The Marker value is invalid.")
	}
	return markerParam(c)
}

// assignmentStatusParam reads AssignmentStatus. It defaults to Any and rejects
// every other value as AWS does.
func assignmentStatusParam(c *exchange) (iam.MFADeviceAssignment, error) {
	switch raw := c.form("AssignmentStatus"); raw {
	case "", string(iam.MFADeviceAssignmentAny):
		return iam.MFADeviceAssignmentAny, nil
	case string(iam.MFADeviceAssignmentAssigned):
		return iam.MFADeviceAssignmentAssigned, nil
	case string(iam.MFADeviceAssignmentUnassigned):
		return iam.MFADeviceAssignmentUnassigned, nil
	default:
		return "", resource.Invalid("assignmentStatus", "1 validation error detected: Value '"+raw+
			"' at 'assignmentStatus' failed to satisfy constraint: "+
			"Member must satisfy enum value set: [Unassigned, Assigned, Any]")
	}
}
