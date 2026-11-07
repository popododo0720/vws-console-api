package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AWS lists Expired as a status; VWS refuses it with its own message (#396).
func TestCheckAccessKeyStatusRefusesExpired(t *testing.T) {
	for _, tc := range []struct {
		status string
		code   resource.Code
		msg    string
	}{
		{iam.AccessKeyActive, resource.CodeUnspecified, ""},
		{iam.AccessKeyInactive, resource.CodeUnspecified, ""},
		{iam.AccessKeyExpired, resource.CodeInvalidArgument, iam.AccessKeyExpiredMessage},
		{"expired", resource.CodeInvalidArgument, "1 validation error detected: Value 'expired' at 'status' " +
			"failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]"},
		{"", resource.CodeInvalidArgument, "1 validation error detected: Value null at 'status' " +
			"failed to satisfy constraint: Member must not be null"},
	} {
		err := iam.CheckAccessKeyStatus(tc.status)
		if got := resource.CodeOf(err); got != tc.code {
			t.Errorf("status %q: code %v, want %v (%v)", tc.status, got, tc.code, err)
			continue
		}
		if tc.msg != "" && resource.AsError(err).Message != tc.msg {
			t.Errorf("status %q: message %q, want %q", tc.status, resource.AsError(err).Message, tc.msg)
		}
	}
}
