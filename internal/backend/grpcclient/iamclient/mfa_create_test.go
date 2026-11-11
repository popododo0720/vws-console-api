package iamclient

import (
	"bytes"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// testSeed is the base32 seed the fake vws-iam returns. A test that finds it
// in a log, a span or an error has found a leak.
const testSeed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// testURI is the otpauth URI vws-iam builds for a device and seed.
func testURI(name, seed string) string {
	u := url.URL{
		Scheme: "otpauth", Host: "totp", Path: "/VWS:" + name,
		RawQuery: url.Values{"secret": {seed}, "issuer": {"VWS"}, "period": {"30"}, "digits": {"6"}}.Encode(),
	}
	return u.String()
}

// The create carries the project, the device name as its id and the path,
// under a deadline, and answers the serial number, seed and URI vws-iam
// returned.
func TestCreateVirtualMFADeviceOverGRPC(t *testing.T) {
	c, s := harness(t)
	got, err := STSAdmin{Client: c}.CreateVirtualMFADevice(t.Context(), accountID(t), "alice-phone", "/eng/", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := iam.NewVirtualMFADevice{
		SerialNumber:     "arn:vws:iam::123456789012:mfa/eng/alice-phone",
		Base32StringSeed: testSeed, OtpauthURI: testURI("alice-phone", testSeed),
	}
	if got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if len(s.createMfa) != 1 {
		t.Fatalf("sent %v", s.createMfa)
	}
	req := s.createMfa[0]
	if req.GetParent() != "projects/123456789012" || req.GetMfaDeviceId() != "alice-phone" ||
		req.GetMfaDevice().GetSpec().GetPath() != "/eng/" {
		t.Errorf("create request %v", req)
	}
	if s.noDeadline != 0 {
		t.Errorf("%d calls without a deadline", s.noDeadline)
	}
	if _, err := (STSAdmin{Client: c}).CreateVirtualMFADevice(
		t.Context(), accountID(t), "bob-phone", "", nil,
	); err != nil {
		t.Fatal(err)
	}
	if p := s.createMfa[1].GetMfaDevice().GetSpec().GetPath(); p != "/" {
		t.Errorf("default path %q, want /", p)
	}
}

// The create's tags go to vws-iam in the same request, in order. The refusals
// are the rows of TestFakeCreateVirtualMFADeviceTags: more than MaxTags tags is
// LimitExceeded, a bad tag or an aws: key or value is InvalidInput on Tags, and
// none of them reaches vws-iam, so no device is created.
func TestCreateVirtualMFADeviceForwardsTags(t *testing.T) {
	c, s := harness(t)
	tags := []iam.Tag{{Key: "team", Value: "eng"}, {Key: "Env", Value: ""}}
	if _, err := (STSAdmin{Client: c}).CreateVirtualMFADevice(t.Context(), accountID(t), "tagged", "/", tags); err != nil {
		t.Fatal(err)
	}
	got := s.createMfa[0].GetTags()
	if len(got) != 2 || got[0].GetKey() != "team" || got[0].GetValue() != "eng" ||
		got[1].GetKey() != "Env" || got[1].GetValue() != "" {
		t.Errorf("sent tags %v", got)
	}
	tooMany := make([]iam.Tag, iam.MaxTags+1)
	for i := range tooMany {
		tooMany[i] = iam.Tag{Key: "k" + strconv.Itoa(i)}
	}
	for name, tc := range map[string]struct {
		tags []iam.Tag
		code resource.Code
		msg  string
	}{
		"51 tags":    {tooMany, resource.CodeResourceExhausted, iam.MFADeviceTagsExceeded().Error()},
		"bad key":    {[]iam.Tag{{Key: "bad#key", Value: "v"}}, resource.CodeInvalidArgument, "tags.member.key"},
		"aws: key":   {[]iam.Tag{{Key: "aws:owner", Value: "v"}}, resource.CodeInvalidArgument, "reserved prefix"},
		"aws: value": {[]iam.Tag{{Key: "team", Value: "aws:x"}}, resource.CodeInvalidArgument, "reserved prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			c, s := harness(t)
			_, err := STSAdmin{Client: c}.CreateVirtualMFADevice(t.Context(), accountID(t), "tagged", "/", tc.tags)
			if resource.CodeOf(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("got %v, want %v %q", err, tc.code, tc.msg)
			}
			var e *resource.Error
			if tc.code == resource.CodeInvalidArgument && (!errors.As(err, &e) || e.Field != "Tags") {
				t.Errorf("field of %v is not Tags, so it is not InvalidInput", err)
			}
			if len(s.createMfa) != 0 {
				t.Fatalf("sent %v", s.createMfa)
			}
		})
	}
}

// The create is sent once: without a request_id a retry after a lost response
// could not get the seed back, so UNAVAILABLE is ServiceUnavailable at once.
func TestCreateVirtualMFADeviceIsNotRetried(t *testing.T) {
	c, s := harness(t)
	s.createMfaErr = status.Error(codes.Unavailable, "response lost")
	_, err := STSAdmin{Client: c}.CreateVirtualMFADevice(t.Context(), accountID(t), "alice-phone", "/", nil)
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
	if len(s.createMfa) != 1 {
		t.Fatalf("sent %d creates, want 1", len(s.createMfa))
	}
}

// Input the surface would refuse is refused here too, before any call.
func TestCreateVirtualMFADeviceValidatesFirst(t *testing.T) {
	for name, tc := range map[string]struct{ name, path string }{
		"empty name": {"", "/"},
		"bad name":   {"a b", "/"},
		"long name":  {strings.Repeat("a", 227), "/"},
		"bad path":   {"alice-phone", "eng"},
	} {
		t.Run(name, func(t *testing.T) {
			c, s := harness(t)
			_, err := STSAdmin{Client: c}.CreateVirtualMFADevice(t.Context(), accountID(t), tc.name, tc.path, nil)
			if resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
			if len(s.createMfa) != 0 {
				t.Fatalf("sent %v", s.createMfa)
			}
		})
	}
}

// Each vws-iam failure maps to the AWS error of the action, and a malformed
// answer is an internal fault that names no secret.
func TestCreateVirtualMFADeviceErrorsOverGRPC(t *testing.T) {
	is := func(code resource.Code) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			if resource.CodeOf(err) != code {
				t.Fatalf("got %v, want %v", err, code)
			}
		}
	}
	answer := func(serial, seed, uri string) *iamv1.CreateVirtualMfaDeviceResponse {
		return &iamv1.CreateVirtualMfaDeviceResponse{
			MfaDevice:        &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{SerialNumber: serial}},
			Base32StringSeed: seed, OtpauthUri: uri,
		}
	}
	serial := "arn:vws:iam::123456789012:mfa/alice-phone"
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *server)
		check func(t *testing.T, err error)
	}{
		{"exists", func(_ *testing.T, s *server) {
			s.createMfaErr = awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
		}, func(t *testing.T, err error) {
			t.Helper()
			if resource.CodeOf(err) != resource.CodeAlreadyExists || err.Error() != iam.MFADeviceExists().Error() {
				t.Fatalf("got %v, want EntityAlreadyExists", err)
			}
		}},
		{"aborted", func(_ *testing.T, s *server) {
			s.createMfaErr = status.Error(codes.Aborted, "store conflict")
		}, func(t *testing.T, err error) {
			t.Helper()
			if !iam.IsChanged(err) {
				t.Fatalf("got %v, want ConcurrentModification", err)
			}
		}},
		{"precondition marked ConcurrentModification", func(t *testing.T, s *server) {
			s.createMfaErr = awsStatus(t, codes.FailedPrecondition, "ConcurrentModification", "changed").Err()
		}, func(t *testing.T, err error) {
			t.Helper()
			if !iam.IsChanged(err) {
				t.Fatalf("got %v, want ConcurrentModification", err)
			}
		}},
		{"quota", func(t *testing.T, s *server) {
			s.createMfaErr = awsStatus(t, codes.ResourceExhausted, "LimitExceeded", "too many devices").Err()
		}, is(resource.CodeResourceExhausted)},
		{"invalid", func(_ *testing.T, s *server) {
			s.createMfaErr = status.Error(codes.InvalidArgument, "mfa device id must match")
		}, is(resource.CodeInvalidArgument)},
		{"deadline", func(_ *testing.T, s *server) {
			s.createMfaErr = status.Error(codes.DeadlineExceeded, "slow")
		}, is(resource.CodeUnavailable)},
		{"another serial", func(_ *testing.T, s *server) {
			s.createMfaRes = answer("arn:vws:iam::123456789012:mfa/eng/alice-phone", testSeed, testURI("alice-phone", testSeed))
		}, is(resource.CodeInternal)},
		{"no seed", func(_ *testing.T, s *server) {
			s.createMfaRes = answer(serial, "", testURI("alice-phone", testSeed))
		}, is(resource.CodeInternal)},
		{"seed not base32", func(_ *testing.T, s *server) {
			s.createMfaRes = answer(serial, "not-base32!", testURI("alice-phone", "not-base32!"))
		}, is(resource.CodeInternal)},
		{"URI without the seed", func(_ *testing.T, s *server) {
			s.createMfaRes = answer(serial, testSeed, testURI("alice-phone", "AAAAAAAA"))
		}, is(resource.CodeInternal)},
		{"not an otpauth URI", func(_ *testing.T, s *server) {
			s.createMfaRes = answer(serial, testSeed, "https://example.invalid/?secret="+testSeed)
		}, is(resource.CodeInternal)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			tc.setup(t, s)
			_, err := STSAdmin{Client: c}.CreateVirtualMFADevice(t.Context(), accountID(t), "alice-phone", "/", nil)
			tc.check(t, err)
			if strings.Contains(err.Error(), testSeed) {
				t.Errorf("error carries the seed: %v", err)
			}
			if len(s.createMfa) != 1 {
				t.Fatalf("sent %d creates, want 1", len(s.createMfa))
			}
		})
	}
}

// The seed and the URI appear only in the result: never in a span, a log
// record or an error, on success or on a malformed answer. The change is one
// structured record naming the device path.
func TestCreateVirtualMFADeviceSeedIsNeverLoggedOrTraced(t *testing.T) {
	rec := spanRecorder()
	before := len(rec.Ended())
	var buf bytes.Buffer
	c, s := harness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	a := STSAdmin{Client: c}
	dev, err := a.CreateVirtualMFADevice(t.Context(), accountID(t), "alice-phone", "/eng/", nil)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(slog.NewJSONHandler(&buf, nil)).InfoContext(t.Context(), "result", slog.Any("device", dev))
	leaked := "KRUGS4ZANFZSA43FMNZGK5BAONSWKZBA"
	s.createMfaRes = &iamv1.CreateVirtualMfaDeviceResponse{
		MfaDevice: &iamv1.MfaDevice{Status: &iamv1.MfaDeviceStatus{
			SerialNumber: "arn:vws:iam::123456789012:mfa/bob-phone",
		}},
		Base32StringSeed: leaked, OtpauthUri: testURI("bob-phone", "MISMATCH"),
	}
	_, bad := a.CreateVirtualMFADevice(t.Context(), accountID(t), "bob-phone", "/", nil)
	if bad == nil {
		t.Fatal("a malformed answer was accepted")
	}
	var seen strings.Builder
	seen.WriteString(buf.String())
	seen.WriteString(bad.Error())
	seen.WriteString(dev.String())
	seen.WriteString(dev.GoString())
	var actions []string
	for _, sp := range rec.Ended()[before:] {
		seen.WriteString(sp.Name() + sp.Status().Description)
		for _, kv := range sp.Attributes() {
			seen.WriteString(string(kv.Key) + "=" + kv.Value.String())
			if kv.Key == "vws.iam.action" {
				actions = append(actions, kv.Value.AsString())
			}
		}
		for _, ev := range sp.Events() {
			seen.WriteString(ev.Name)
			for _, kv := range ev.Attributes {
				seen.WriteString(kv.Value.String())
			}
		}
	}
	for _, secret := range []string{testSeed, leaked, "secret="} {
		if strings.Contains(seen.String(), secret) {
			t.Errorf("a secret (%s) appears in a span, log record or error: %s", secret, seen.String())
		}
	}
	if !strings.Contains(strings.Join(actions, " "), "CreateVirtualMFADevice") {
		t.Errorf("no CreateVirtualMFADevice span in %q", actions)
	}
	if !strings.Contains(buf.String(), `"action":"CreateVirtualMFADevice"`) ||
		!strings.Contains(buf.String(), `"mfa_device":"mfa/eng/alice-phone"`) ||
		!strings.Contains(buf.String(), `"outcome":"ok"`) {
		t.Errorf("no structured CreateVirtualMFADevice record naming the device: %s", buf.String())
	}
}
