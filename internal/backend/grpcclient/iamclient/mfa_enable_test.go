package iamclient

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	enableUser    = "projects/123456789012/users/alice"
	enableUserARN = "arn:vws:iam::123456789012:user/alice"
	enableMoved   = "arn:vws:iam::123456789012:user/denied/alice"
)

// enableHarness is a vws-iam with user alice at enableUserARN and an
// unassigned device at mfaSerial.
func enableHarness(t *testing.T) (STSAdmin, *server) {
	t.Helper()
	c, s := harness(t)
	s.getUserRes = map[string]*iamv1.User{enableUser: {Name: enableUser, Status: &iamv1.UserStatus{Arn: enableUserARN}}}
	s.getMfaRes = &iamv1.MfaDevice{
		Name: "projects/123456789012/mfaDevices/alice-phone", Status: &iamv1.MfaDeviceStatus{SerialNumber: mfaSerial},
	}
	return STSAdmin{Client: c}, s
}

func enable(t *testing.T, a STSAdmin, serial string, want iam.AuthorizedPrincipal) error {
	t.Helper()
	return a.EnableMFADevice(t.Context(), accountID(t), "alice", serial, "908172", "817263", want)
}

// The enable names the device read by its exact serial number and the user,
// and carries both codes.
func TestEnableMFADeviceOverGRPC(t *testing.T) {
	a, s := enableHarness(t)
	if err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN)); err != nil {
		t.Fatal(err)
	}
	if len(s.enableMfa) != 1 {
		t.Fatalf("sent %v", s.enableMfa)
	}
	req := s.enableMfa[0]
	if req.GetName() != "projects/123456789012/mfaDevices/alice-phone" || req.GetUser() != enableUser ||
		req.GetAuthenticationCode_1() != "908172" || req.GetAuthenticationCode_2() != "817263" {
		t.Errorf("enable request name=%s user=%s", req.GetName(), req.GetUser())
	}
	if len(s.deactivateMfa) != 0 {
		t.Errorf("deactivated a device it enabled: %v", s.deactivateMfa)
	}
}

// A lost response is retried. The codes are single use, so vws-iam answers
// the retry EntityAlreadyExists. Nothing proves that enrollment is this
// call's (vws-proto#125), so the call is a ServiceFailure: not claimed as
// success, and not undone, since it may be a concurrent request's.
func TestEnableMFADeviceLostResponseIsUnknown(t *testing.T) {
	a, s := enableHarness(t)
	s.enableMfaFailFirst, s.enableMfaLands = 1, true
	err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN))
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v, want ServiceFailure", err)
	}
	if len(s.enableMfa) != 2 {
		t.Fatalf("sent %d enables, want 2", len(s.enableMfa))
	}
	if len(s.deactivateMfa) != 0 {
		t.Fatalf("undid an enrollment it cannot prove is its own: %v", s.deactivateMfa)
	}

	// EntityAlreadyExists on the first attempt is the AWS error.
	a, s = enableHarness(t)
	s.enableMfaErr = awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	err = enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN))
	if resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("got %v, want EntityAlreadyExists", err)
	}
}

// A user read after the enable that fails cannot prove the user is still at
// the authorized ARN, so the device is deactivated again and the call fails.
func TestEnableMFADeviceUnverifiedUserIsUndone(t *testing.T) {
	a, s := enableHarness(t)
	s.onCall = func(method string) {
		if method == "EnableMfaDevice" {
			s.getUserErr = status.Error(codes.Unavailable, vwsIAMMsg)
		}
	}
	if err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN)); err == nil {
		t.Fatal("succeeded with the user unverified after the enable")
	}
	if len(s.enableMfa) != 1 {
		t.Fatalf("sent %d enables, want 1", len(s.enableMfa))
	}
	if len(s.deactivateMfa) != 1 || s.deactivateMfa[0].GetName() != "projects/123456789012/mfaDevices/alice-phone" ||
		s.deactivateMfa[0].GetUser() != enableUser {
		t.Fatalf("not undone: %v", s.deactivateMfa)
	}
}

// The re-check after an unverified enable may use up its whole deadline, as
// a vws-iam that stopped answering GetUser would make it. The undo still runs
// under a live deadline of its own instead of the re-check's expired one.
func TestEnableMFADeviceUndoOutlivesTheRecheck(t *testing.T) {
	a, s := enableHarness(t)
	a.undoTimeout = 200 * time.Millisecond
	s.onCall = func(method string) {
		if method == "EnableMfaDevice" {
			s.getUserHang = true
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err := a.EnableMFADevice(ctx, accountID(t), "alice", mfaSerial, "908172", "817263",
		backendtest.Grant(t.Context(), t, enableUserARN))
	if err == nil {
		t.Fatal("succeeded with the user unverified after the enable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.getUser) < 3 {
		t.Fatalf("sent %d user reads, want the bind, the check and the re-check", len(s.getUser))
	}
	if len(s.deactivateMfa) != 1 || s.deactivateMfa[0].GetName() != "projects/123456789012/mfaDevices/alice-phone" ||
		s.deactivateMfa[0].GetUser() != enableUser {
		t.Fatalf("not undone after the re-check used up its deadline: %v", s.deactivateMfa)
	}
	if s.deactivateCtxErr[0] != nil {
		t.Fatalf("undo ran on an ended context: %v", s.deactivateCtxErr[0])
	}
}

// DeactivateMfaDevice carries no request id or precondition (vws-proto#125),
// so a retry after a lost response could deactivate a newer enrollment. An
// undo answered UNAVAILABLE is therefore sent exactly once, logged without
// the codes, and the call is ServiceFailure.
func TestEnableMFADeviceUndoIsSentOnce(t *testing.T) {
	var buf bytes.Buffer
	a, s := enableHarness(t)
	a.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s.deactivateMfaErr = status.Error(codes.Unavailable, "response lost")
	s.onCall = func(method string) {
		if method == "EnableMfaDevice" {
			s.getUserErr = status.Error(codes.Unavailable, vwsIAMMsg)
		}
	}
	err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN))
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v, want ServiceFailure", err)
	}
	if len(s.deactivateMfa) != 1 {
		t.Fatalf("sent %d deactivations, want exactly 1", len(s.deactivateMfa))
	}
	logged := buf.String()
	if !strings.Contains(logged, "undo outcome unknown") || !strings.Contains(logged, "mfa/alice-phone") {
		t.Fatalf("unknown undo outcome not logged: %s", logged)
	}
	if strings.Contains(logged, "123456789012") {
		t.Fatalf("account id leaked into the undo log: %s", logged)
	}
	for _, code := range []string{"908172", "817263"} {
		if strings.Contains(logged+err.Error(), code) {
			t.Errorf("authentication code %s leaked: %s %v", code, logged, err)
		}
	}
}

// A user moved to another path while the device was enabled gets the device
// deactivated again, and the call is ConcurrentModification. A user moved
// before the call is refused before anything is sent.
func TestEnableMFADeviceBindsTheUser(t *testing.T) {
	a, s := enableHarness(t)
	s.onCall = func(method string) {
		if method == "EnableMfaDevice" {
			s.getUserRes[enableUser] = &iamv1.User{Name: enableUser, Status: &iamv1.UserStatus{Arn: enableMoved}}
		}
	}
	if err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN)); !iam.IsChanged(err) {
		t.Fatalf("user moved during the enable: %v", err)
	}
	if len(s.deactivateMfa) != 1 || s.deactivateMfa[0].GetName() != "projects/123456789012/mfaDevices/alice-phone" ||
		s.deactivateMfa[0].GetUser() != enableUser {
		t.Fatalf("not undone: %v", s.deactivateMfa)
	}

	a, s = enableHarness(t)
	s.getUserRes[enableUser] = &iamv1.User{Name: enableUser, Status: &iamv1.UserStatus{Arn: enableMoved}}
	if err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN)); !iam.IsChanged(err) {
		t.Fatalf("user moved before the enable: %v", err)
	}
	if len(s.enableMfa) != 0 {
		t.Fatalf("enabled for a moved user: %v", s.enableMfa)
	}

	a, s = enableHarness(t)
	if err := enable(t, a, mfaSerial, iam.AuthorizedPrincipal{}); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("zero AuthorizedPrincipal: %v", err)
	}
	if len(s.getUser) != 0 || len(s.enableMfa) != 0 {
		t.Fatalf("read or wrote with a zero AuthorizedPrincipal: %v %v", s.getUser, s.enableMfa)
	}
}

func TestEnableMFADeviceErrorsOverGRPC(t *testing.T) {
	is := func(code resource.Code, field string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			e := resource.AsError(err)
			if e.Code != code || e.Field != field {
				t.Fatalf("got %v (%s/%s), want %s/%s", err, e.Code, e.Field, code, field)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		setup   func(s *server)
		serial  string
		check   func(*testing.T, error)
		enables int
	}{
		{"missing device", func(s *server) {
			s.getMfaErr = status.Error(codes.NotFound, "no such device")
		}, mfaSerial, is(resource.CodeNotFound, ""), 0},
		{"same name on another path", func(s *server) {
			s.getMfaRes.Status.SerialNumber = "arn:vws:iam::123456789012:mfa/eng/alice-phone"
		}, mfaSerial, is(resource.CodeNotFound, ""), 0},
		{"another account", func(*server) {}, mfaForeign, is(resource.CodeNotFound, ""), 0},
		{"missing user", func(s *server) {
			s.getUserRes = map[string]*iamv1.User{}
		}, mfaSerial, is(resource.CodeNotFound, ""), 0},
		{"device in use", func(s *server) {
			s.getMfaRes.Status.User = "projects/123456789012/users/bob"
		}, mfaSerial, is(resource.CodeAlreadyExists, ""), 0},
		{"wrong codes", func(s *server) {
			s.enableMfaErr = awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode")
		}, mfaSerial, is(resource.CodePermissionDenied, iam.InvalidAuthenticationCode), 1},
		{"enabled since the read", func(s *server) {
			s.enableMfaErr = awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
		}, mfaSerial, is(resource.CodeAlreadyExists, ""), 1},
		{"user renamed or replaced", func(s *server) {
			s.enableMfaErr = awsErr(codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
		}, mfaSerial, is(resource.CodeConflict, iam.EntityTemporarilyUnmodifiable), 1},
		{"user deleted since the read", func(s *server) {
			s.enableMfaErr = awsErr(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
		}, mfaSerial, is(resource.CodeNotFound, ""), 1},
		{"limit", func(s *server) {
			s.enableMfaErr = awsErr(codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
		}, mfaSerial, is(resource.CodeResourceExhausted, ""), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s := enableHarness(t)
			tc.setup(s)
			tc.check(t, enable(t, a, tc.serial, backendtest.Grant(t.Context(), t, enableUserARN)))
			if len(s.enableMfa) != tc.enables {
				t.Fatalf("sent %d enables, want %d", len(s.enableMfa), tc.enables)
			}
		})
	}
}

// Neither authentication code reaches a log record, a span or an error, on
// success and when vws-iam rejects the codes.
func TestEnableMFADeviceCodesAreNeverLoggedOrTraced(t *testing.T) {
	rec := spanRecorder()
	before := len(rec.Ended())
	var buf bytes.Buffer
	a, s := enableHarness(t)
	a.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN)); err != nil {
		t.Fatal(err)
	}
	s.enableMfaErr = awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode")
	rejected := enable(t, a, mfaSerial, backendtest.Grant(t.Context(), t, enableUserARN))
	if resource.AsError(rejected).Field != iam.InvalidAuthenticationCode {
		t.Fatalf("rejected codes: %v", rejected)
	}
	var seen strings.Builder
	seen.WriteString(buf.String() + rejected.Error())
	spans := rec.Ended()[before:]
	if len(spans) == 0 {
		t.Fatal("no span for EnableMFADevice")
	}
	for _, sp := range spans {
		seen.WriteString(sp.Name() + sp.Status().Description)
		for _, kv := range sp.Attributes() {
			seen.WriteString(string(kv.Key) + "=" + kv.Value.String())
		}
	}
	for _, code := range []string{"908172", "817263"} {
		if strings.Contains(seen.String(), code) {
			t.Errorf("authentication code %s leaked: %s", code, seen.String())
		}
	}
}
