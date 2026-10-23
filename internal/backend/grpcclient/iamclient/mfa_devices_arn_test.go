package iamclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// #330 r2: over gRPC, ListMFADevices returns devices only while the user is
// at the ARN the caller was authorized on. A user that moved after the
// authorization (or after the caller authenticated, without UserName), or
// while the devices were being listed, is 409 ConcurrentModification with no
// device in the answer.
func TestListMFADevicesActsOnTheAuthorizedARNOverGRPC(t *testing.T) {
	const (
		alice       = "projects/123456789012/users/alice"
		bob         = "projects/123456789012/users/bob"
		aliceSerial = "arn:vws:iam::123456789012:mfa/alice-phone"
		bobSerial   = "arn:vws:iam::123456789012:mfa/bob-phone"
	)
	enabled := timestamppb.New(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC))
	moved := func(s *server, name, path string) {
		u := s.getUserRes[name]
		arn := "arn:vws:iam::123456789012:user" + path + name[strings.LastIndex(name, "/")+1:]
		s.getUserRes[name] = &iamv1.User{
			Name: u.GetName(), Spec: &iamv1.UserSpec{Path: path},
			Status: &iamv1.UserStatus{Arn: arn, UniqueId: u.GetStatus().GetUniqueId()}, CreateTime: u.GetCreateTime(),
		}
	}
	for _, tc := range []struct {
		name   string
		form   url.Values
		serial string
		// authorized is the ARN the request must be authorized on: the
		// user's ARN before any move.
		authorized string
		// setup changes what vws-iam holds; nil leaves the users in place.
		setup func(s *server)
		code  int
	}{
		{
			name: "a named user that stays", form: url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}},
			serial: aliceSerial, authorized: aliceARN, code: http.StatusOK,
		},
		{
			name: "the caller that stays", form: url.Values{"Action": {"ListMFADevices"}},
			serial: bobSerial, authorized: bobARN, code: http.StatusOK,
		},
		{
			// The surface's lookup is the first read of alice; she moves
			// right after it answers.
			name: "a named user moved after the authorization",
			form: url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}, serial: aliceSerial, authorized: aliceARN,
			setup: func(s *server) {
				reads := 0
				s.onCall = func(method string) {
					if method != "GetUser" || s.getUser[len(s.getUser)-1].GetName() != alice {
						return
					}
					if reads++; reads == 2 {
						moved(s, alice, "/denied/")
					}
				}
			},
			code: http.StatusConflict,
		},
		{
			// bob authenticated as user/eng/bob and then moved.
			name: "the caller moved after authenticating",
			form: url.Values{"Action": {"ListMFADevices"}}, serial: bobSerial, authorized: bobARN,
			setup: func(s *server) { moved(s, bob, "/denied/") },
			code:  http.StatusConflict,
		},
		{
			name: "a named user moved while the devices were listed",
			form: url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}, serial: aliceSerial, authorized: aliceARN,
			setup: func(s *server) {
				s.onCall = func(method string) {
					if method == "ListMfaDevices" {
						moved(s, alice, "/denied/")
					}
				}
			},
			code: http.StatusConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s := queryHarness(t)
			s.mu.Lock()
			s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{
				{Status: &iamv1.MfaDeviceStatus{SerialNumber: aliceSerial, User: alice, EnableTime: enabled}},
				{Status: &iamv1.MfaDeviceStatus{SerialNumber: bobSerial, User: bob, EnableTime: enabled}},
			}}
			if tc.setup != nil {
				tc.setup(s)
			}
			s.mu.Unlock()
			res := queryCall(t, h, tc.form)
			s.mu.Lock()
			var resources []string
			for _, a := range s.authz {
				if a.GetAction() == "iam:ListMFADevices" {
					resources = append(resources, a.GetResources()...)
				}
			}
			s.mu.Unlock()
			if len(resources) != 1 || resources[0] != tc.authorized {
				t.Fatalf("authorized on %q, want %q", resources, tc.authorized)
			}
			if tc.code == http.StatusOK {
				expect(t, res, http.StatusOK, "<SerialNumber>"+tc.serial+"</SerialNumber>")
				return
			}
			expect(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
			if body := res.Body.String(); strings.Contains(body, tc.serial) || strings.Contains(body, "<MFADevices>") {
				t.Errorf("a moved user's devices were answered: %s", body)
			}
		})
	}
}
