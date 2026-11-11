package iam

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// The fake creates a device at its serial number with a fresh seed whose URI
// carries it, refuses a second device of the same name on any path, and
// validates name and path like AWS.
func TestFakeCreateVirtualMFADevice(t *testing.T) {
	ctx := t.Context()
	f := NewFake()
	a := account(t)
	dev, err := f.CreateVirtualMFADevice(ctx, a, "alice-phone", "/eng/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if dev.SerialNumber != "arn:vws:iam::123456789012:mfa/eng/alice-phone" {
		t.Errorf("serial %q", dev.SerialNumber)
	}
	if err := CheckEnrollment(dev.Base32StringSeed, dev.OtpauthURI); err != nil {
		t.Errorf("fake enrollment: %v", err)
	}
	other, err := f.CreateVirtualMFADevice(ctx, a, "bob-phone", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if other.Base32StringSeed == dev.Base32StringSeed {
		t.Error("two devices share a seed")
	}
	if other.SerialNumber != "arn:vws:iam::123456789012:mfa/bob-phone" {
		t.Errorf("default path serial %q", other.SerialNumber)
	}
	for _, path := range []string{"/eng/", "/"} {
		_, err := f.CreateVirtualMFADevice(ctx, a, "alice-phone", path, nil)
		if resource.CodeOf(err) != resource.CodeAlreadyExists || err.Error() != MFADeviceExists().Error() {
			t.Errorf("duplicate at %s: %v", path, err)
		}
	}
	for _, tc := range []struct{ name, path string }{
		{"", "/"}, {"a b", "/"}, {strings.Repeat("a", MaxVirtualMFADeviceNameLen+1), "/"}, {"x", "eng"},
	} {
		_, err := f.CreateVirtualMFADevice(ctx, a, tc.name, tc.path, nil)
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("%q %q: %v, want InvalidArgument", tc.name, tc.path, err)
		}
	}
}

// The fake stores the create's tags on the device. The tags it refuses are the
// shared contract, TestFakeCreateMFADeviceTagContract.
func TestFakeCreateVirtualMFADeviceTags(t *testing.T) {
	ctx := t.Context()
	f := NewFake()
	a := account(t)
	dev, err := f.CreateVirtualMFADevice(ctx, a, "tagged", "/", []Tag{{"team", "eng"}, {"Env", ""}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.ListMFADeviceTags(ctx, a, dev.SerialNumber, "", 0)
	if err != nil || len(page.Tags) != 2 {
		t.Fatalf("tags %v, %v", page.Tags, err)
	}
}

func TestCheckVirtualMFADeviceName(t *testing.T) {
	for name, ok := range map[string]bool{
		"a": true, "Alice+=,.@-_9": true, strings.Repeat("a", 226): true,
		"": false, strings.Repeat("a", 227): false, "a b": false, "a/b": false, "a:b": false,
	} {
		if err := CheckVirtualMFADeviceName(name); (err == nil) != ok {
			t.Errorf("%q: %v", name, err)
		}
	}
}

// A malformed enrollment is an internal fault that never echoes the secret.
func TestCheckEnrollment(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	good := "otpauth://totp/VWS:x?secret=" + seed + "&issuer=VWS"
	if err := CheckEnrollment(seed, good); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ seed, uri string }{
		"no seed":    {"", good},
		"not base32": {"JBSW!", "otpauth://totp/VWS:x?secret=JBSW!"},
		"other seed": {seed, "otpauth://totp/VWS:x?secret=AAAAAAAA"},
		"hotp":       {seed, "otpauth://hotp/VWS:x?secret=" + seed},
		"no URI":     {seed, ""},
	} {
		err := CheckEnrollment(tc.seed, tc.uri)
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("%s: %v, want Internal", name, err)
			continue
		}
		if tc.seed != "" && strings.Contains(err.Error(), tc.seed) {
			t.Errorf("%s: error echoes the seed: %v", name, err)
		}
	}
}

// Printing or logging a new device never shows its seed or URI.
func TestNewVirtualMFADeviceRedactsSeed(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	d := NewVirtualMFADevice{
		SerialNumber: "arn:vws:iam::123456789012:mfa/x", Base32StringSeed: seed,
		OtpauthURI: "otpauth://totp/VWS:x?secret=" + seed,
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).InfoContext(t.Context(), "device", slog.Any("d", d))
	out := buf.String() + fmt.Sprint(d) + fmt.Sprintf("%v %+v %#v %s", d, d, d, d)
	if strings.Contains(out, seed) || strings.Contains(out, "secret=") {
		t.Errorf("seed shown: %s", out)
	}
	if !strings.Contains(out, d.SerialNumber) {
		t.Errorf("serial not shown: %s", out)
	}
}
