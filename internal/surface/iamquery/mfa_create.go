package iamquery

import (
	"encoding/base64"
	"errors"
	"fmt"

	"rsc.io/qr"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// createdVirtualMFADeviceXML is the AWS VirtualMFADevice structure as
// CreateVirtualMFADevice returns it. Base32StringSeed and QRCodePNG are AWS
// blobs, so on the Query wire each is the base64 of its bytes: the base32
// seed text and the PNG image.
type createdVirtualMFADeviceXML struct {
	SerialNumber     string `xml:"SerialNumber"`
	Base32StringSeed string `xml:"Base32StringSeed"`
	QRCodePNG        string `xml:"QRCodePNG"`
}

// createVirtualMFADeviceResult is the CreateVirtualMFADevice result.
type createVirtualMFADeviceResult struct {
	VirtualMFADevice createdVirtualMFADeviceXML `xml:"VirtualMFADevice"`
}

// createVirtualMFADeviceARN validates VirtualMFADeviceName and Path before
// anything is authorized, as AWS does, and authorizes on the serial number
// the device will have: arn:vws:iam::<account>:mfa<path><name>.
func createVirtualMFADeviceARN(_ *handler, c *exchange) string {
	name, path, err := createVirtualMFADeviceParams(c)
	if err != nil {
		c.resourceErr = err
		return ""
	}
	return arnOf(c, "mfa", path, name)
}

// createVirtualMFADeviceParams reads the required VirtualMFADeviceName and the
// optional Path (default "/"). A Path that is present but empty breaks its
// minimum length of 1.
func createVirtualMFADeviceParams(c *exchange) (string, string, error) {
	if !c.r.Form.Has("VirtualMFADeviceName") {
		return "", "", nullMember("virtualMFADeviceName")
	}
	name := c.form("VirtualMFADeviceName")
	if err := iam.CheckVirtualMFADeviceName(name); err != nil {
		return "", "", err
	}
	if c.r.Form.Has("Path") && c.form("Path") == "" {
		return "", "", badMember("path", "Member must have length greater than or equal to 1")
	}
	path, err := iam.NormalizePath("Path", c.form("Path"))
	if err != nil {
		return "", "", err
	}
	return name, path, nil
}

// createVirtualMFADevice runs CreateVirtualMFADevice. The seed and the QR code
// go into the response body only; a failure after the device was made never
// carries either.
func createVirtualMFADevice(h *handler, c *exchange) (any, error) {
	name, path, err := createVirtualMFADeviceParams(c)
	if err != nil {
		return nil, err
	}
	dev, err := h.cfg.Admin.CreateVirtualMFADevice(c.r.Context(), c.caller.Account, name, path)
	if err != nil {
		return nil, err
	}
	png, err := qrCodePNG(dev.OtpauthURI)
	if err != nil {
		return nil, err
	}
	return createVirtualMFADeviceResult{VirtualMFADevice: createdVirtualMFADeviceXML{
		SerialNumber:     iam.AWSPartition(dev.SerialNumber),
		Base32StringSeed: base64.StdEncoding.EncodeToString([]byte(dev.Base32StringSeed)),
		QRCodePNG:        base64.StdEncoding.EncodeToString(png),
	}}, nil
}

// errQRCode is the fault of a URI the QR encoder refused. The URI (it embeds
// the seed) is never part of it.
var errQRCode = errors.New("encode the virtual MFA device QR code")

// qrCodePNG renders the otpauth URI as a PNG QR code at error correction
// level M, which authenticator apps scan.
func qrCodePNG(uri string) ([]byte, error) {
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, resource.Internal(fmt.Errorf("%w: %d-byte URI", errQRCode, len(uri)))
	}
	return code.PNG(), nil
}
