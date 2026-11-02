package iamclient

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// setPassword gives user a console password in the directory.
func setPassword(d *directory, user, pw string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.passwords[fold(user)] = pw
}

// ChangePassword serves UserService.ChangePassword as vws-iam 35f6797
// internal/grpcapi/users.go does: the new password is checked for 8 to 128
// characters first; a missing user, a user with no password or a wrong old
// password is UNAUTHENTICATED INVALID_CREDENTIALS.
func (d *directory) ChangePassword(
	_ context.Context, req *iamv1.ChangePasswordRequest,
) (*iamv1.ChangePasswordResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ChangePassword", req); err != nil {
		return nil, err
	}
	if n := utf8.RuneCountInString(req.GetNewPassword()); n < 8 || n > 128 {
		return nil, awsErr(codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")
	}
	cur, ok := d.passwords[fold(req.GetName())]
	if d.users[fold(req.GetName())] == nil || !ok || cur != req.GetOldPassword() {
		return nil, awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	}
	if d.race > 0 {
		d.race--
		return nil, awsErr(codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
	}
	d.passwords[fold(req.GetName())] = req.GetNewPassword()
	return &iamv1.ChangePasswordResponse{}, nil
}

func TestChangePasswordOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	setPassword(d, "projects/123456789012/users/bob", "old password 1")
	grant := backendtest.UserGrant(ctx, t, a, account314, "bob")

	if err := a.ChangePassword(ctx, account314, "bob", "old password 1", "new password 2", grant); err != nil {
		t.Fatal(err)
	}
	sent := d.sent("ChangePassword")
	if len(sent) != 1 {
		t.Fatalf("ChangePassword calls %d, want 1", len(sent))
	}
	req, ok := sent[0].(*iamv1.ChangePasswordRequest)
	if !ok || req.GetName() != "projects/123456789012/users/bob" ||
		req.GetOldPassword() != "old password 1" || req.GetNewPassword() != "new password 2" {
		t.Fatalf("request %v", sent[0])
	}

	for _, tc := range []struct {
		name, oldPw, newPw string
		code               resource.Code
		field              string
	}{
		{"wrong old password", "old password 1", "third password", resource.CodePermissionDenied, ""},
		{"policy violation", "new password 2", "short", resource.CodeInvalidArgument, "Password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a.ChangePassword(ctx, account314, "bob", tc.oldPw, tc.newPw, grant)
			e := resource.AsError(err)
			if e.Code != tc.code || e.Field != tc.field {
				t.Fatalf("got %v (%q), want %v (%q)", e.Code, e.Field, tc.code, tc.field)
			}
			if strings.Contains(err.Error(), tc.oldPw) || strings.Contains(err.Error(), tc.newPw) {
				t.Fatalf("error carries a password: %v", err)
			}
		})
	}

	d.mu.Lock()
	d.race = 1
	d.mu.Unlock()
	err := a.ChangePassword(ctx, account314, "bob", "new password 2", "third password", grant)
	if e := resource.AsError(err); e.Code != resource.CodeConflict || e.Field != "EntityTemporarilyUnmodifiable" {
		t.Fatalf("lost race: %v", err)
	}

	// No password: vws-iam answers it as a wrong old password.
	err = a.ChangePassword(ctx, account314, "alice", "x password 1", "new password 2",
		backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("alice without a password: %v", err)
	}
}

// A change is sent once: a lost response is not repeated, because a repeat
// would verify the old password against the new hash and deny a change that
// landed. The outage is ServiceUnavailable.
func TestChangePasswordIsNotRetried(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	setPassword(d, "projects/123456789012/users/bob", "old password 1")
	d.mu.Lock()
	d.failBefore["ChangePassword"] = 1
	d.mu.Unlock()
	err := a.ChangePassword(ctx, account314, "bob", "old password 1", "new password 2",
		backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
	if n := len(d.sent("ChangePassword")); n != 1 {
		t.Fatalf("ChangePassword calls %d, want 1", n)
	}
}

func TestChangePasswordBindsTheAuthorizedUser(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	err := a.ChangePassword(ctx, account314, "bob", "old password 1", "new password 2", iam.AuthorizedPrincipal{})
	if err == nil {
		t.Fatal("an unbound change was sent")
	}
	// alice's grant does not change bob.
	err = a.ChangePassword(ctx, account314, "bob", "old password 1", "new password 2",
		backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if !iam.IsChanged(err) {
		t.Fatalf("got %v, want ConcurrentModification", err)
	}
	if n := len(d.sent("ChangePassword")); n != 0 {
		t.Fatalf("ChangePassword calls %d, want 0", n)
	}
}

func TestChangePasswordLogsNoSecret(t *testing.T) {
	var buf bytes.Buffer
	c, d := dirHarness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	a := STSAdmin{Client: c}
	ctx := t.Context()
	if _, err := a.CreateUser(ctx, account314, "carol", "/qa/"); err != nil {
		t.Fatal(err)
	}
	setPassword(d, "projects/123456789012/users/carol", "old secret 1")
	grant := backendtest.UserGrant(ctx, t, a, account314, "carol")
	if err := a.ChangePassword(ctx, account314, "carol", "old secret 1", "new secret 2", grant); err != nil {
		t.Fatal(err)
	}
	if err := a.ChangePassword(ctx, account314, "carol", "old secret 1", "new secret 3", grant); err == nil {
		t.Fatal("a wrong old password was accepted")
	}
	out := buf.String()
	if !strings.Contains(out, `"action":"ChangePassword"`) || !strings.Contains(out, `"outcome":"PermissionDenied"`) {
		t.Fatalf("log %s", out)
	}
	for _, s := range []string{"old secret 1", "new secret 2", "new secret 3"} {
		if strings.Contains(out, s) {
			t.Fatalf("log carries a password: %s", out)
		}
	}
}

func TestChangePasswordErrorKeepsNonStatusErrors(t *testing.T) {
	want := errors.New("boom")
	if got := changePasswordError(want, "bob"); !errors.Is(got, want) {
		t.Fatalf("got %v", got)
	}
	got := changePasswordError(status.Error(codes.NotFound, "x"), "bob")
	if resource.CodeOf(got) != resource.CodeNotFound {
		t.Fatalf("got %v", got)
	}
}
