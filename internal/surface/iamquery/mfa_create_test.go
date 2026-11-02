package iamquery

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/xml"
	"image/png"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func createMFAForm(name, path string) url.Values {
	v := url.Values{"Action": {"CreateVirtualMFADevice"}, "VirtualMFADeviceName": {name}}
	if path != "" {
		v.Set("Path", path)
	}
	return v
}

// createdDevice decodes the VirtualMFADevice of a CreateVirtualMFADevice
// response: the seed as the base32 text it encodes and the QR code image.
func createdDevice(t *testing.T, body []byte) (serial string, key, qr []byte) {
	t.Helper()
	var doc struct {
		Device struct {
			SerialNumber     string
			Base32StringSeed string
			QRCodePNG        string
		} `xml:"CreateVirtualMFADeviceResult>VirtualMFADevice"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Device.Base32StringSeed)
	if err != nil {
		t.Fatalf("Base32StringSeed is not base64: %v", err)
	}
	key, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(raw))
	if err != nil || len(key) == 0 {
		t.Fatalf("Base32StringSeed does not carry a base32 seed: %v", err)
	}
	qr, err = base64.StdEncoding.DecodeString(doc.Device.QRCodePNG)
	if err != nil {
		t.Fatalf("QRCodePNG is not base64: %v", err)
	}
	return doc.Device.SerialNumber, key, qr
}

// CreateVirtualMFADevice answers the AWS VirtualMFADevice shape, with the
// seed and the QR code PNG base64 encoded as AWS blobs, is authorized as
// iam:CreateVirtualMFADevice on the serial number the device gets, and the
// seed it returns enables the device.
func TestCreateVirtualMFADevice(t *testing.T) {
	h, f, rec, root := harness(t)
	res := call(t, h, root, sigv4.ServiceIAM, createMFAForm("alice-phone", "/eng/"))
	has(t, res, http.StatusOK, `<CreateVirtualMFADeviceResponse>`,
		`<CreateVirtualMFADeviceResult><VirtualMFADevice>`+
			`<SerialNumber>arn:vws:iam::123456789012:mfa/eng/alice-phone</SerialNumber><Base32StringSeed>`,
		`</Base32StringSeed><QRCodePNG>`, `<ResponseMetadata><RequestId>`)
	serial, seed, qr := createdDevice(t, res.Body.Bytes())
	if serial != "arn:vws:iam::123456789012:mfa/eng/alice-phone" {
		t.Errorf("serial %q", serial)
	}
	if !bytes.HasPrefix(qr, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("QRCodePNG is not a PNG: % x", qr[:min(8, len(qr))])
	}
	if _, err := png.Decode(bytes.NewReader(qr)); err != nil {
		t.Fatalf("QRCodePNG does not decode: %v", err)
	}
	want := "iam:CreateVirtualMFADevice arn:vws:iam::123456789012:mfa/eng/alice-phone"
	if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
		t.Errorf("not authorized as %s: %v", want, rec.seen)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusOK, `<SerialNumber>`+serial+`</SerialNumber>`)
	if _, err := f.CreateUser(t.Context(), root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	enable := url.Values{
		"Action": {"EnableMFADevice"}, "UserName": {"alice"}, "SerialNumber": {serial},
		"AuthenticationCode1": {iam.TOTPCode(seed, now.Add(-30*time.Second))},
		"AuthenticationCode2": {iam.TOTPCode(seed, now)},
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, enable), http.StatusOK, `<EnableMFADeviceResponse>`)
	// Path defaults to "/", and a name of 226 characters is accepted.
	long := strings.Repeat("a", iam.MaxVirtualMFADeviceNameLen)
	has(t, call(t, h, root, sigv4.ServiceIAM, createMFAForm(long, "")),
		http.StatusOK, `<SerialNumber>arn:vws:iam::123456789012:mfa/`+long+`</SerialNumber>`)
}

// Each documented error maps to its AWS code and HTTP status, and a Tags
// member is refused before anything is created.
func TestCreateVirtualMFADeviceErrors(t *testing.T) {
	h, _, _, root := harness(t)
	has(t, call(t, h, root, sigv4.ServiceIAM, createMFAForm("alice-phone", "/eng/")), http.StatusOK)
	for name, tc := range map[string]struct {
		form   url.Values
		status int
		want   []string
	}{
		"same name and path": {
			createMFAForm("alice-phone", "/eng/"), http.StatusConflict,
			[]string{`<Code>EntityAlreadyExists</Code>`, `<Message>` + iam.MFADeviceExistsMsg + `</Message>`},
		},
		"same name other path": {
			createMFAForm("alice-phone", "/"), http.StatusConflict, []string{`<Code>EntityAlreadyExists</Code>`},
		},
		"no name": {
			url.Values{"Action": {"CreateVirtualMFADevice"}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `&#39;virtualMFADeviceName&#39;`},
		},
		"empty name": {
			createMFAForm("", ""), http.StatusBadRequest, []string{`<Code>ValidationError</Code>`},
		},
		"name too long": {
			createMFAForm(strings.Repeat("a", iam.MaxVirtualMFADeviceNameLen+1), ""), http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `length less than or equal to 226`},
		},
		"bad name": {
			createMFAForm("alice phone", ""), http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `[\w+=,.@-]+`},
		},
		"empty path": {
			url.Values{"Action": {"CreateVirtualMFADevice"}, "VirtualMFADeviceName": {"x"}, "Path": {""}},
			http.StatusBadRequest,
			[]string{`<Code>ValidationError</Code>`, `&#39;path&#39;`},
		},
		"bad path": {
			createMFAForm("x", "eng"), http.StatusBadRequest, []string{`<Code>InvalidInput</Code>`},
		},
		"tags": {
			func() url.Values {
				v := createMFAForm("tagged", "/")
				v.Set("Tags.member.1.Key", "team")
				v.Set("Tags.member.1.Value", "eng")
				return v
			}(), http.StatusBadRequest, []string{`<Code>InvalidInput</Code>`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			has(t, call(t, h, root, sigv4.ServiceIAM, tc.form), tc.status, tc.want...)
		})
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}})
	has(t, res, http.StatusOK)
	if n := strings.Count(res.Body.String(), "<SerialNumber>"); n != 1 {
		t.Errorf("a refused create left a device behind: %s", res.Body.String())
	}
}

// AWS validates every member before it authorizes; a well-formed request
// from a caller without permission is AccessDenied and creates nothing.
func TestCreateVirtualMFADeviceValidationPrecedesAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	bob := callerWithoutPermissions(t, f, root)
	for name, form := range map[string]url.Values{
		"no name":    {"Action": {"CreateVirtualMFADevice"}},
		"long name":  createMFAForm(strings.Repeat("a", 227), ""),
		"bad name":   createMFAForm("a b", ""),
		"empty path": {"Action": {"CreateVirtualMFADevice"}, "VirtualMFADeviceName": {"x"}, "Path": {""}},
		"bad path":   createMFAForm("x", "eng"),
	} {
		t.Run(name, func(t *testing.T) {
			rec.seen = nil
			res := call(t, h, bob, sigv4.ServiceIAM, form)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("got %d: %s", res.Code, res.Body.String())
			}
			if len(rec.seen) != 0 {
				t.Errorf("authorized before validation: %v", rec.seen)
			}
		})
	}
	res := call(t, h, bob, sigv4.ServiceIAM, createMFAForm("bob-phone", "/"))
	has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if strings.Contains(res.Body.String(), "Base32StringSeed") {
		t.Errorf("a denied create returned a seed: %s", res.Body.String())
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusOK, `<VirtualMFADevices></VirtualMFADevices>`)
}

// stubCreateMFA answers CreateVirtualMFADevice with a fixed device or error,
// for what the fake cannot reach: a quota, a lost race, a backend fault.
type stubCreateMFA struct {
	iam.Directory
	dev iam.NewVirtualMFADevice
	err error
}

func (s stubCreateMFA) CreateVirtualMFADevice(
	context.Context, resource.AccountID, string, string,
) (iam.NewVirtualMFADevice, error) {
	return s.dev, s.err
}

func TestCreateVirtualMFADeviceBackendErrors(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	for _, tc := range []struct {
		name   string
		stub   stubCreateMFA
		status int
		code   string
	}{
		{
			"limit",
			stubCreateMFA{err: &resource.Error{Code: resource.CodeResourceExhausted, Message: "too many devices"}},
			http.StatusConflict, "LimitExceeded",
		},
		{
			"lost race",
			stubCreateMFA{err: iam.Changed(iam.MFADeviceChanged)},
			http.StatusConflict, "ConcurrentModification",
		},
		{
			"invalid at vws-iam",
			stubCreateMFA{err: &resource.Error{Code: resource.CodeInvalidArgument, Message: "bad name"}},
			http.StatusBadRequest, "InvalidInput",
		},
		{
			"backend fault",
			stubCreateMFA{err: resource.Internal(context.DeadlineExceeded)},
			http.StatusInternalServerError, "ServiceFailure",
		},
		{
			"backend down",
			stubCreateMFA{err: &resource.Error{Code: resource.CodeUnavailable, Message: "down"}},
			http.StatusServiceUnavailable, "ServiceUnavailable",
		},
		{
			"URI too long for a QR code",
			stubCreateMFA{dev: iam.NewVirtualMFADevice{
				SerialNumber: "arn:vws:iam::123456789012:mfa/x", Base32StringSeed: seed,
				OtpauthURI: "otpauth://totp/VWS:x?secret=" + seed + "&pad=" + strings.Repeat("A", 4000),
			}},
			http.StatusInternalServerError, "ServiceFailure",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _, root := harnessWith(t, func(d iam.Directory) iam.Directory {
				s := tc.stub
				s.Directory = d
				return s
			})
			res := call(t, h, root, sigv4.ServiceIAM, createMFAForm("x", "/"))
			has(t, res, tc.status, `<Code>`+tc.code+`</Code>`)
			if strings.Contains(res.Body.String(), seed) ||
				strings.Contains(res.Body.String(), base64.StdEncoding.EncodeToString([]byte(seed))) {
				t.Errorf("an error response carries the seed: %s", res.Body.String())
			}
		})
	}
}
