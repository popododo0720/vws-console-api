package iamquery

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// DeleteVirtualMFADevice answers an empty result in the AWS envelope, is
// authorized on the device's serial number, and the device is gone afterwards.
func TestDeleteVirtualMFADevice(t *testing.T) {
	h, f, rec, root := harness(t)
	serial := f.AddMfaDevice(root.Account, "spare-phone")
	keep := f.AddMfaDevice(root.Account, "other-phone")

	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {serial}})
	has(t, res, http.StatusOK, `<DeleteVirtualMFADeviceResponse>`, `<ResponseMetadata><RequestId>`)
	if body := res.Body.String(); strings.Contains(body, "<DeleteVirtualMFADeviceResult>") ||
		strings.Contains(body, "spare-phone") {
		t.Errorf("DeleteVirtualMFADevice returned more than the empty AWS result: %s", body)
	}
	if !strings.Contains(strings.Join(rec.seen, "\n"), "iam:DeleteVirtualMFADevice "+serial) {
		t.Errorf("not authorized as iam:DeleteVirtualMFADevice on %s: %v", serial, rec.seen)
	}
	list := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}})
	has(t, list, http.StatusOK, `<SerialNumber>`+iam.AWSPartition(keep)+`</SerialNumber>`)
	if strings.Contains(list.Body.String(), iam.AWSPartition(serial)) {
		t.Errorf("deleted device still listed: %s", list.Body.String())
	}
	// A second delete of the same device is NoSuchEntity, as in AWS.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {serial}}),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`, `<Message>The specified MFA device does not exist.</Message>`)
}

// The documented errors map to the AWS code and HTTP status: NoSuchEntity 404
// for a device the account does not hold and DeleteConflict 409 for a device
// still enabled for a user, which stays.
func TestDeleteVirtualMFADeviceErrors(t *testing.T) {
	h, f, _, root := harness(t)
	if _, err := f.CreateUser(t.Context(), root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	enabled := f.AddMfaDevice(root.Account, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, enabled, "alice", now); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {enabled}}),
		http.StatusConflict, `<Code>DeleteConflict</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusOK, `<SerialNumber>`+iam.AWSPartition(enabled)+`</SerialNumber>`)

	for name, serial := range map[string]string{
		"missing":       "arn:vws:iam::123456789012:mfa/ghost-phone",
		"other account": "arn:vws:iam::210987654321:mfa/alice-phone",
		"other path":    "arn:vws:iam::123456789012:mfa/eng/alice-phone",
	} {
		t.Run(name, func(t *testing.T) {
			has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
				"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {serial},
			}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
		})
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {enabled}, "UserName": {"alice"},
	}), http.StatusBadRequest)
}

// A caller without iam:DeleteVirtualMFADevice is AccessDenied and the device
// stays.
func TestDeleteVirtualMFADeviceNeedsPermission(t *testing.T) {
	h, f, _, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	serial := f.AddMfaDevice(root.Account, "spare-phone")
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {serial}}),
		http.StatusForbidden, `<Code>AccessDenied</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusOK, `<SerialNumber>`+iam.AWSPartition(serial)+`</SerialNumber>`)
}
