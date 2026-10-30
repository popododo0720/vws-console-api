package iamclient

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #331: a user that moves to a denied path while the device pages are read
// and moves back before the final user read passes both ARN checks (ABA).
// vws-iam changes the user's etag on every write, so the two reads carry
// different etags and the answer is ConcurrentModification with no device.
func TestListMFADevicesDetectsAMoveAndMoveBackOverGRPC(t *testing.T) {
	const (
		alice     = "projects/123456789012/users/alice"
		aliceARN  = "arn:vws:iam::123456789012:user/alice"
		deniedARN = "arn:vws:iam::123456789012:user/denied/alice"
		serialA   = "arn:vws:iam::123456789012:mfa/alice-a"
		serialB   = "arn:vws:iam::123456789012:mfa/alice-b"
	)
	user := func(arn, etag string) *iamv1.User {
		return &iamv1.User{Name: alice, Etag: etag, Status: &iamv1.UserStatus{Arn: arn}}
	}
	enabled := timestamppb.New(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC))
	c, s := harness(t)
	s.getUserRes = map[string]*iamv1.User{alice: user(aliceARN, "1")}
	s.listMfaDevicesPages = map[string]*iamv1.ListMfaDevicesResponse{
		"": {MfaDevices: []*iamv1.MfaDevice{{Status: &iamv1.MfaDeviceStatus{
			SerialNumber: serialA, User: alice, EnableTime: enabled,
		}}}, NextPageToken: "next"},
		"next": {MfaDevices: []*iamv1.MfaDevice{{Status: &iamv1.MfaDeviceStatus{
			SerialNumber: serialB, User: alice, EnableTime: enabled,
		}}}},
	}
	pages := 0
	s.onCall = func(method string) {
		if method != "ListMfaDevices" {
			return
		}
		switch pages++; pages {
		case 1: // UpdateUser NewPath /denied/ before the first page answers
			s.getUserRes[alice] = user(deniedARN, "2")
		case 2: // and back to / before the second page answers
			s.getUserRes[alice] = user(aliceARN, "3")
		}
	}
	page, err := (STSAdmin{Client: c}).ListMFADevices(
		t.Context(), accountID(t), "alice", "", 0, backendtest.Grant(t.Context(), t, aliceARN),
	)
	if pages != 2 {
		t.Fatalf("read %d device pages, want 2", pages)
	}
	if !iam.IsChanged(err) || len(page.Devices) != 0 {
		t.Fatalf("a user moved away and back across the device pages: %+v, %v", page, err)
	}

	// No write in between: the etag stays and the devices are served.
	c, s = harness(t)
	s.getUserRes = map[string]*iamv1.User{alice: user(aliceARN, "1")}
	s.listMfaDevicesPages = map[string]*iamv1.ListMfaDevicesResponse{
		"": {MfaDevices: []*iamv1.MfaDevice{{Status: &iamv1.MfaDeviceStatus{
			SerialNumber: serialA, User: alice, EnableTime: enabled,
		}}}},
	}
	page, err = (STSAdmin{Client: c}).ListMFADevices(
		t.Context(), accountID(t), "alice", "", 0, backendtest.Grant(t.Context(), t, aliceARN),
	)
	if err != nil || len(page.Devices) != 1 {
		t.Fatalf("an unchanged user: %+v, %v", page, err)
	}
}

// #331: the same ABA for ListAccessKeys. bob moves to a denied path while
// the key pages are read and moves back before the final user read; the
// answer is ConcurrentModification with no key.
func TestListAccessKeysDetectsAMoveAndMoveBackOverGRPC(t *testing.T) {
	ctx := t.Context()
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	if _, err := a.CreateUser(ctx, account314, "bob", "/eng/"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob")); err != nil {
			t.Fatal(err)
		}
	}
	want := backendtest.UserGrant(ctx, t, a, account314, "bob")
	d.mu.Lock()
	d.maxPage = 1
	pages := 0
	d.onListAccessKeys = func(d *directory) {
		u := d.users[fold("projects/"+account314.String()+"/users/bob")]
		switch pages++; pages {
		case 1: // UpdateUser NewPath /denied/ before the first page answers
			u.path, u.version = "/denied/", u.version+1
		case 2: // and back to /eng/ before the second page answers
			u.path, u.version = "/eng/", u.version+1
		}
	}
	d.mu.Unlock()
	ks, err := a.ListAccessKeys(ctx, account314, "bob", want)
	if pages != 2 {
		t.Fatalf("read %d key pages, want 2", pages)
	}
	if !iam.IsChanged(err) || len(ks) != 0 {
		t.Fatalf("a user moved away and back across the key pages: %v, %v", ks, err)
	}

	// No write in between: the etag stays and both keys are served.
	d.mu.Lock()
	d.onListAccessKeys = nil
	d.mu.Unlock()
	ks, err = a.ListAccessKeys(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil || len(ks) != 2 {
		t.Fatalf("an unchanged user: %v, %v", ks, err)
	}
}

// #331: a user read without an etag cannot show that it did not change, so
// the list fails closed: an internal error with no device and no key.
func TestListsFailClosedOnAUserWithoutAnEtagOverGRPC(t *testing.T) {
	const (
		bob    = "projects/123456789012/users/bob"
		bobARN = "arn:vws:iam::123456789012:user/bob"
	)
	c, s := harness(t)
	s.noUserEtag = true
	s.getUserRes = map[string]*iamv1.User{bob: {Name: bob, Status: &iamv1.UserStatus{Arn: bobARN}}}
	s.listMfaDevicesRes = &iamv1.ListMfaDevicesResponse{MfaDevices: []*iamv1.MfaDevice{{Status: &iamv1.MfaDeviceStatus{
		SerialNumber: "arn:vws:iam::123456789012:mfa/bob-phone", User: bob,
		EnableTime: timestamppb.New(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)),
	}}}}
	page, err := (STSAdmin{Client: c}).ListMFADevices(
		t.Context(), accountID(t), "bob", "", 0, backendtest.Grant(t.Context(), t, bobARN),
	)
	if resource.CodeOf(err) != resource.CodeInternal || len(page.Devices) != 0 {
		t.Fatalf("ListMFADevices of a user without an etag: %+v, %v", page, err)
	}
	if len(s.listMfaDevices) != 0 {
		t.Fatalf("listed devices of a user without an etag: %v", s.listMfaDevices)
	}
	ks, err := (STSAdmin{Client: c}).ListAccessKeys(
		t.Context(), accountID(t), "bob", backendtest.Grant(t.Context(), t, bobARN),
	)
	if resource.CodeOf(err) != resource.CodeInternal || len(ks) != 0 {
		t.Fatalf("ListAccessKeys of a user without an etag: %v, %v", ks, err)
	}
}
