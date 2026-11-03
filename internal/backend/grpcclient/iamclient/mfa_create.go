package iamclient

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// CreateVirtualMFADevice implements iam.Admin over
// MfaDeviceService.CreateVirtualMfaDevice, which answers synchronously with
// the device, its base32 seed and its otpauth URI.
//
// The call is sent once and never retried: CreateVirtualMfaDeviceRequest has
// no request_id (vws-proto#129), so a retry after a lost response that did
// commit would be refused as EntityAlreadyExists and the seed, which vws-iam
// returns only here, would be lost either way. A transport failure is ServiceUnavailable;
// the caller may find the device with ListVirtualMFADevices and delete it.
//
// The seed and the URI are checked (non-empty, base32, URI carries the seed)
// and returned; they are never put in a span, a log record or an error.
// The span and the log name the device by its account-free path only
// ("mfa/eng/alice-phone").
func (a STSAdmin) CreateVirtualMFADevice(
	ctx context.Context, account resource.AccountID, name, path string,
) (out iam.NewVirtualMFADevice, err error) {
	start := time.Now()
	device := "mfa" + path + name
	ctx, end := a.observe(ctx, "CreateVirtualMFADevice", false, account, "", "")
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("vws.iam.mfa_device", device))
	defer func() {
		end(err)
		a.logMFAChange(ctx, "CreateVirtualMFADevice", device, start, err)
	}()
	if err := iam.CheckVirtualMFADeviceName(name); err != nil {
		return iam.NewVirtualMFADevice{}, err
	}
	path, err = iam.NormalizePath("Path", path)
	if err != nil {
		return iam.NewVirtualMFADevice{}, err
	}
	device = "mfa" + path + name
	resp, err := call(ctx, a.mfaDevices.CreateVirtualMfaDevice, &iamv1.CreateVirtualMfaDeviceRequest{
		Parent: projectName(account), MfaDeviceId: name,
		MfaDevice: &iamv1.MfaDevice{Spec: &iamv1.MfaDeviceSpec{Path: path}},
	})
	if err != nil {
		return iam.NewVirtualMFADevice{}, mfaCreateError(err)
	}
	serial := resp.GetMfaDevice().GetStatus().GetSerialNumber()
	if want := iam.VirtualMFADeviceSerial(account, path, name); serial != want {
		return iam.NewVirtualMFADevice{}, resource.Internal(
			errors.New("vws-iam CreateVirtualMfaDevice returned another serial number"))
	}
	if err := iam.CheckEnrollment(resp.GetBase32StringSeed(), resp.GetOtpauthUri()); err != nil {
		return iam.NewVirtualMFADevice{}, err
	}
	return iam.NewVirtualMFADevice{
		SerialNumber: serial, Base32StringSeed: resp.GetBase32StringSeed(), OtpauthURI: resp.GetOtpauthUri(),
	}, nil
}

// mfaCreateError maps a vws-iam failure of CreateVirtualMFADevice to the AWS
// errors of the action: ALREADY_EXISTS is EntityAlreadyExists with the AWS
// message, ABORTED (or FAILED_PRECONDITION marked ConcurrentModification) is
// ConcurrentModification, RESOURCE_EXHAUSTED is LimitExceeded and
// INVALID_ARGUMENT is InvalidInput (authError keeps those two), and a
// transport failure is ServiceUnavailable without vws-iam's message.
func mfaCreateError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() { //nolint:exhaustive // the rest is authError's.
	case codes.AlreadyExists:
		return iam.MFADeviceExists()
	case codes.Aborted:
		return iam.Changed(iam.MFADeviceChanged)
	case codes.FailedPrecondition:
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetMetadata()["aws_code"] == "ConcurrentModification" {
				return iam.Changed(iam.MFADeviceChanged)
			}
		}
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return backendUnavailable(err)
	}
	return authError(err)
}

// logMFAChange writes the structured record of a virtual MFA device change:
// the action, the account-free device path, the outcome and the elapsed time,
// and for a fault the error. Neither the seed nor the URI ever reaches it.
func (a STSAdmin) logMFAChange(ctx context.Context, action, device string, start time.Time, err error) {
	outcome := "ok"
	if err != nil {
		outcome = resource.CodeOf(err).String()
	}
	level := slog.LevelInfo
	attrs := []slog.Attr{
		slog.String("action", action), slog.String("mfa_device", device),
		slog.String("outcome", outcome), slog.Duration("elapsed", time.Since(start)),
	}
	if c := resource.CodeOf(err); c == resource.CodeUnavailable || c == resource.CodeInternal {
		level = slog.LevelWarn
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	a.logger().LogAttrs(ctx, level, "vws-iam virtual MFA device change", attrs...)
}
