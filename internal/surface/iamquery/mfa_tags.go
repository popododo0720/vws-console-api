package iamquery

import (
	"regexp"

	"github.com/popododo0720/vws-console-api/internal/iam"
)

// serialNumberRE matches the AWS SerialNumber parameter: letters, digits and
// _ + = / : , . @ -.
var serialNumberRE = regexp.MustCompile(`^[\w+=/:,.@-]+$`)

// mfaDeviceARN is the ARN a virtual MFA device call is authorized on: in AWS
// the device SerialNumber is its ARN.
func mfaDeviceARN(_ *handler, c *exchange) string { return c.form("SerialNumber") }

// requireMFADevice checks SerialNumber (required, 9 to 256 characters of
// [\w+=/:,.@-]) and applies the AWS rule that adding a tag also needs
// permission to list the device's tags.
func requireMFADevice(c *exchange, h *handler, action string) error {
	serial := c.form("SerialNumber")
	if serial == "" {
		return nullMember("serialNumber")
	}
	if n := len(serial); n < 9 || n > 256 {
		return badMember("serialNumber", "Member must have length between 9 and 256")
	}
	if !serialNumberRE.MatchString(serial) {
		return badMember("serialNumber", `Member must satisfy regular expression pattern: [\w+=/:,.@-]+`)
	}
	// AWS requires the list permission only to add tags, not to remove them.
	if action == "iam:TagMFADevice" {
		if err := iam.Check(c.r.Context(), h.cfg.Authorizer, c.caller, "iam:ListMFADeviceTags", serial); err != nil {
			return err
		}
	}
	return nil
}
