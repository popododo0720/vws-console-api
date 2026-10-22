package iamquery

import (
	"regexp"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// listUserNameRE is the AWS UserName pattern.
var listUserNameRE = regexp.MustCompile(`^[\w+=,.@-]+$`)

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

// mfaDeviceXML is the AWS MFADevice structure.
type mfaDeviceXML struct {
	UserName     string `xml:"UserName"`
	SerialNumber string `xml:"SerialNumber"`
	EnableDate   string `xml:"EnableDate"`
}

// mfaDevicesResult is the ListMFADevices result.
type mfaDevicesResult struct {
	MFADevices  []mfaDeviceXML `xml:"MFADevices>member"`
	IsTruncated bool           `xml:"IsTruncated"`
	Marker      string         `xml:"Marker,omitempty"`
}

func toMFADevice(d iam.MFADevice) mfaDeviceXML {
	return mfaDeviceXML{
		UserName: d.UserName, SerialNumber: d.SerialNumber, EnableDate: stamp(d.EnableDate),
	}
}

// listMFADevicesUserName reads ListMFADevices UserName. AWS requires 1 to 128
// characters from its user name pattern; when the member is omitted the
// caller's user is used.
func listMFADevicesUserName(c *exchange) (string, error) {
	if !c.r.Form.Has("UserName") {
		return requireUser(c)
	}
	if err := rejectEmpty(c, "UserName"); err != nil {
		return "", err
	}
	name := c.form("UserName")
	if len(name) > 128 {
		return "", badMember("userName", "Member must have length less than or equal to 128")
	}
	if !listUserNameRE.MatchString(name) {
		return "", badMember("userName", `Member must satisfy regular expression pattern: [\w+=,.@-]+`)
	}
	return name, nil
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
