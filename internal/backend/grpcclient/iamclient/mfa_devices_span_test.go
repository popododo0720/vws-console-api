package iamclient

import (
	"testing"
	"time"

	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ListMFADevices leaves one client span, as ListAccessKeys does, with its
// outcome: ok on success, and Conflict with an error status when the user
// moved while the devices were listed (409 ConcurrentModification, #410).
func TestListMFADevicesIsTraced(t *testing.T) {
	const (
		alice  = "projects/123456789012/users/alice"
		serial = "arn:vws:iam::123456789012:mfa/alice-phone"
	)
	rec := spanRecorder()
	for _, tc := range []struct {
		name    string
		move    bool
		outcome string
	}{
		{name: "success", outcome: "ok"},
		{name: "user moved", move: true, outcome: resource.CodeConflict.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			s.getUserRes = map[string]*iamv1.User{alice: {
				Name:   alice,
				Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/alice"},
			}}
			s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{{
				Status: &iamv1.MfaDeviceStatus{
					SerialNumber: serial, User: alice,
					EnableTime: timestamppb.New(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)),
				},
			}}}
			if tc.move {
				s.onCall = func(method string) {
					if method == "ListMfaDevices" {
						s.getUserRes[alice] = &iamv1.User{
							Name:   alice,
							Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/denied/alice"},
						}
					}
				}
			}
			before := len(rec.Ended())
			_, err := (STSAdmin{Client: c}).ListMFADevices(
				t.Context(), accountID(t), "alice", "", 0,
				backendtest.Grant(t.Context(), t, "arn:vws:iam::123456789012:user/alice"),
			)
			if tc.move != iam.IsChanged(err) || (!tc.move && err != nil) {
				t.Fatalf("ListMFADevices: %v", err)
			}
			var got []sdktrace.ReadOnlySpan
			for _, sp := range rec.Ended()[before:] {
				if sp.Name() == "vws-iam ListMFADevices" {
					got = append(got, sp)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%d ListMFADevices spans, want 1", len(got))
			}
			attrs := map[string]string{}
			for _, kv := range got[0].Attributes() {
				attrs[string(kv.Key)] = kv.Value.AsString()
			}
			if attrs["vws.iam.outcome"] != tc.outcome || attrs["vws.iam.user_name"] != "alice" ||
				attrs["vws.iam.action"] != "ListMFADevices" {
				t.Errorf("span attributes %v, want outcome %s for alice", attrs, tc.outcome)
			}
			if wantErr := tc.move; (got[0].Status().Code == otelcodes.Error) != wantErr {
				t.Errorf("span status %v", got[0].Status())
			}
		})
	}
}
