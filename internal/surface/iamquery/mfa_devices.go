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

// listedMFADeviceXML is one row of ListMFADevices. EnableDate is required by
// the AWS MFADevice type.
type listedMFADeviceXML struct {
	UserName     string `xml:"UserName"`
	SerialNumber string `xml:"SerialNumber"`
	EnableDate   string `xml:"EnableDate"`
}

// mfaDevicesResult is the ListMFADevices result.
type mfaDevicesResult struct {
	MFADevices  []listedMFADeviceXML `xml:"MFADevices>member"`
	IsTruncated bool                 `xml:"IsTruncated"`
	Marker      string               `xml:"Marker,omitempty"`
}

func toListedMFADevice(d iam.MFADevice) listedMFADeviceXML {
	return listedMFADeviceXML{
		UserName: d.UserName, SerialNumber: d.SerialNumber, EnableDate: stamp(d.Enabled),
	}
}

// listMFADevicesUserName reads ListMFADevices UserName. The pre-authorization
// hook validates a present name; when the member is omitted the caller's user
// is used.
func listMFADevicesUserName(c *exchange) (string, error) {
	if !c.r.Form.Has("UserName") {
		return requireUser(c)
	}
	return c.form("UserName"), nil
}

// mfaDeviceMarkerParam checks the Marker of the MFA device list actions. AWS
// gives it a minimum length of 1 and the same character range as the other
// list markers.
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
