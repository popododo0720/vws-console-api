package iam

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// enableFixture is a fake at a fixed time with user alice and an unassigned
// TOTP device.
func enableFixture(
	ctx context.Context, t *testing.T,
) (*Fake, resource.AccountID, string, []byte, time.Time, AuthorizedPrincipal) {
	t.Helper()
	at := time.Date(2026, 11, 3, 2, 0, 15, 0, time.UTC)
	f := NewFake()
	f.Now = func() time.Time { return at }
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.CreateUser(ctx, account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("12345678901234567890")
	serial := f.AddTOTPMfaDevice(account, "alice-phone", seed)
	return f, account, serial, seed, at, testGrant(ctx, t, u.ARN)
}

// RFC 6238 appendix B: the SHA-1 seed "12345678901234567890" gives 94287082
// at 59 s, so the six-digit code is 287082.
func TestTOTPCodeMatchesRFC6238(t *testing.T) {
	if got := TOTPCode([]byte("12345678901234567890"), time.Unix(59, 0)); got != "287082" {
		t.Fatalf("TOTPCode = %s, want 287082", got)
	}
	if got := TOTPCode([]byte("12345678901234567890"), time.Unix(1111111109, 0)); got != "081804" {
		t.Fatalf("TOTPCode = %s, want 081804", got)
	}
}

// Two consecutive codes enable the device for the user, and ListMFADevices
// then reports it with the enable time.
func TestFakeEnableMFADevice(t *testing.T) {
	ctx := t.Context()
	f, account, serial, seed, at, grant := enableFixture(ctx, t)
	c1, c2 := TOTPCode(seed, at.Add(-30*time.Second)), TOTPCode(seed, at)
	if err := f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, grant); err != nil {
		t.Fatal(err)
	}
	page, err := f.ListMFADevices(ctx, account, "alice", "", 0, grant)
	if err != nil || len(page.Devices) != 1 || page.Devices[0].SerialNumber != serial ||
		!page.Devices[0].Enabled.Equal(at) {
		t.Fatalf("after enable: %+v, %v", page, err)
	}
	// The device is now in use, also for the same codes again.
	err = f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, grant)
	if resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("second enable: %v", err)
	}
}

func TestFakeEnableMFADeviceErrors(t *testing.T) {
	ctx := t.Context()
	invalidCode := func(t *testing.T, err error) {
		t.Helper()
		e := resource.AsError(err)
		if e.Code != resource.CodePermissionDenied || e.Field != InvalidAuthenticationCode {
			t.Fatalf("got %v, want InvalidAuthenticationCode", err)
		}
	}
	for _, tc := range []struct {
		name  string
		codes func(seed []byte, at time.Time) (string, string)
		check func(t *testing.T, err error)
	}{
		{"wrong first code", func(seed []byte, at time.Time) (string, string) {
			return "000000", TOTPCode(seed, at)
		}, invalidCode},
		{"codes not consecutive", func(seed []byte, at time.Time) (string, string) {
			return TOTPCode(seed, at.Add(-60*time.Second)), TOTPCode(seed, at)
		}, invalidCode},
		{"codes swapped", func(seed []byte, at time.Time) (string, string) {
			return TOTPCode(seed, at), TOTPCode(seed, at.Add(-30*time.Second))
		}, invalidCode},
		{"codes too old", func(seed []byte, at time.Time) (string, string) {
			return TOTPCode(seed, at.Add(-90*time.Second)), TOTPCode(seed, at.Add(-60*time.Second))
		}, invalidCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			f, account, serial, seed, at, grant := enableFixture(ctx, t)
			c1, c2 := tc.codes(seed, at)
			tc.check(t, f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, grant))
			if page, _ := f.ListMFADevices(ctx, account, "alice", "", 0, grant); len(page.Devices) != 0 {
				t.Fatalf("a refused enable left a device: %+v", page)
			}
		})
	}

	f, account, serial, seed, at, grant := enableFixture(ctx, t)
	c1, c2 := TOTPCode(seed, at.Add(-30*time.Second)), TOTPCode(seed, at)
	if err := f.EnableMFADevice(ctx, account, "nobody", serial, c1, c2, testGrant(ctx, t,
		"arn:vws:iam::123456789012:user/nobody")); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing user: %v", err)
	}
	for _, other := range []string{
		"arn:vws:iam::123456789012:mfa/ghost-phone",
		"arn:vws:iam::123456789012:mfa/eng/alice-phone",
		"arn:vws:iam::210987654321:mfa/alice-phone",
	} {
		if err := f.EnableMFADevice(ctx, account, "alice", other, c1, c2, grant); err == nil ||
			err.Error() != MFADeviceNotFound().Error() {
			t.Fatalf("device %s: %v", other, err)
		}
	}
	// A device added without a seed accepts no code.
	plain := f.AddMfaDevice(account, "plain-phone")
	err := f.EnableMFADevice(ctx, account, "alice", plain, c1, c2, grant)
	if resource.AsError(err).Field != InvalidAuthenticationCode {
		t.Fatalf("seedless device: %v", err)
	}
	// A user at another ARN than the authorized one keeps no device.
	moved := testGrant(ctx, t, "arn:vws:iam::123456789012:user/denied/alice")
	if err := f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, moved); !IsChanged(err) {
		t.Fatalf("moved user: %v", err)
	}
	err = f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, AuthorizedPrincipal{})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("zero AuthorizedPrincipal: %v", err)
	}
	if page, _ := f.ListMFADevices(ctx, account, "alice", "", 0, grant); len(page.Devices) != 0 {
		t.Fatalf("a refused enable left a device: %+v", page)
	}
}

// A code already accepted is not accepted again: after the device is
// deactivated outside the API, the same pair is InvalidAuthenticationCode.
func TestFakeEnableMFADeviceRefusesReusedCodes(t *testing.T) {
	ctx := t.Context()
	f, account, serial, seed, at, grant := enableFixture(ctx, t)
	c1, c2 := TOTPCode(seed, at.Add(-30*time.Second)), TOTPCode(seed, at)
	if err := f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, grant); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.account(account).mfa[serial].user = ""
	f.mu.Unlock()
	err := f.EnableMFADevice(ctx, account, "alice", serial, c1, c2, grant)
	if resource.AsError(err).Field != InvalidAuthenticationCode {
		t.Fatalf("reused codes: %v", err)
	}
}
