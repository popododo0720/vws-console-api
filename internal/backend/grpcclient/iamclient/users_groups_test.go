package iamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

var account314 = func() resource.AccountID {
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		panic(err)
	}
	return a
}()

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// seeded is a directory client with alice (/ops/) in devs (/team/) and bob
// (/eng/).
func seeded(ctx context.Context, t *testing.T) (STSAdmin, *directory) {
	t.Helper()
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	for _, u := range [][2]string{{"alice", "/ops/"}, {"bob", "/eng/"}} {
		if _, err := a.CreateUser(ctx, account314, u[0], u[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.CreateGroup(ctx, account314, "devs", "/team/"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddUserToGroup(
		ctx, account314, "devs", "alice", backendtest.GroupGrant(ctx, t, a, account314, "devs"),
	); err != nil {
		t.Fatal(err)
	}
	return a, d
}

// Requests carry the vws-iam resource names, the path, a UUID request_id
// and, on updates, the etag read and a mask on only the changed field.
func TestUserAndGroupRequestsOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	cu := d.sent("CreateUser")[0].(*iamv1.CreateUserRequest)
	if cu.GetParent() != "projects/123456789012" || cu.GetUserId() != "alice" ||
		cu.GetUser().GetSpec().GetPath() != "/ops/" || !uuidV4.MatchString(cu.GetRequestId()) {
		t.Errorf("CreateUser sent %v", cu)
	}
	cg := d.sent("CreateGroup")[0].(*iamv1.CreateGroupRequest)
	if cg.GetGroupId() != "devs" || cg.GetGroup().GetSpec().GetPath() != "/team/" ||
		!uuidV4.MatchString(cg.GetRequestId()) {
		t.Errorf("CreateGroup sent %v", cg)
	}
	ug := d.sent("UpdateGroup")[0].(*iamv1.UpdateGroupRequest)
	if ug.GetGroup().GetName() != "projects/123456789012/groups/devs" || ug.GetGroup().GetEtag() != "1" ||
		strings.Join(ug.GetUpdateMask().GetPaths(), ",") != "spec.members" ||
		strings.Join(ug.GetGroup().GetSpec().GetMembers(), ",") != "projects/123456789012/users/alice" {
		t.Errorf("AddUserToGroup sent %v", ug)
	}
	if err := a.UpdateUser(
		ctx, account314, "bob", "/sre/", "", backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	uu := d.sent("UpdateUser")[0].(*iamv1.UpdateUserRequest)
	if uu.GetUser().GetName() != "projects/123456789012/users/bob" || uu.GetUser().GetEtag() != "1" ||
		strings.Join(uu.GetUpdateMask().GetPaths(), ",") != "spec.path" || uu.GetUser().GetSpec().GetPath() != "/sre/" {
		t.Errorf("UpdateUser sent %v", uu)
	}
	if cu.GetRequestId() == cg.GetRequestId() || cu.GetRequestId() == uu.GetRequestId() {
		t.Error("request ids repeat across calls")
	}
	// Nothing to change sends nothing.
	if err := a.UpdateUser(
		ctx, account314, "bob", "/sre/", "", backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	if err := a.AddUserToGroup(
		ctx, account314, "devs", "alice", backendtest.GroupGrant(ctx, t, a, account314, "devs"),
	); err != nil {
		t.Fatal(err)
	}
	if n, m := len(d.sent("UpdateUser")), len(d.sent("UpdateGroup")); n != 1 || m != 1 {
		t.Errorf("no-op changes sent %d UpdateUser and %d UpdateGroup", n, m)
	}
}

// A retry after a lost response replays the request_id, so the change lands
// once; a vws-iam that stays down is a retryable ServiceUnavailable.
func TestUserAndGroupMutationsRetrySafely(t *testing.T) {
	ctx := t.Context()
	t.Run("CreateUser response lost", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failAfter["CreateUser"] = 1
		d.mu.Unlock()
		u, err := a.CreateUser(ctx, account314, "carol", "/")
		if err != nil || u.Name != "carol" {
			t.Fatalf("CreateUser: %+v %v", u, err)
		}
		sent := d.sent("CreateUser")
		first, second := sent[len(sent)-2].(*iamv1.CreateUserRequest), sent[len(sent)-1].(*iamv1.CreateUserRequest)
		if first.GetRequestId() != second.GetRequestId() {
			t.Errorf("retry used request ids %s and %s", first.GetRequestId(), second.GetRequestId())
		}
	})
	t.Run("DeleteUser response lost", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failAfter["DeleteUser"] = 1
		d.mu.Unlock()
		if err := a.DeleteUser(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob")); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	})
	t.Run("AddUserToGroup response lost", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failAfter["UpdateGroup"] = 1
		d.mu.Unlock()
		if err := a.AddUserToGroup(
			ctx, account314, "devs", "bob", backendtest.GroupGrant(ctx, t, a, account314, "devs"),
		); err != nil {
			t.Fatalf("AddUserToGroup: %v", err)
		}
		_, us, err := a.GetGroup(ctx, account314, "devs", backendtest.GroupGrant(ctx, t, a, account314, "devs"))
		if err != nil || len(us) != 2 {
			t.Fatalf("members %+v %v", us, err)
		}
	})
	t.Run("vws-iam stays down", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failBefore["CreateGroup"] = MaxAttempts
		d.mu.Unlock()
		_, err := a.CreateGroup(ctx, account314, "ops", "/")
		if resource.CodeOf(err) != resource.CodeUnavailable {
			t.Fatalf("CreateGroup: %v", err)
		}
		if n := len(d.sent("CreateGroup")); n != 1+MaxAttempts {
			t.Errorf("%d CreateGroup calls, want 1 seed + %d", n, MaxAttempts)
		}
	})
	t.Run("the caller's deadline stops the retries", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failBefore["ListUsers"] = 100
		d.mu.Unlock()
		short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := a.ListUsers(short, account314, "")
		if resource.CodeOf(err) != resource.CodeUnavailable || time.Since(start) > 2*time.Second {
			t.Fatalf("ListUsers: %v after %v", err, time.Since(start))
		}
	})
}

// AddUserToGroup and RemoveUserFromGroup read the group again when another
// writer moved its etag, and give up with a retryable 503.
func TestMembershipChangesRereadALostRace(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	d.mu.Lock()
	d.race = membershipAttempts - 1
	d.mu.Unlock()
	if err := a.AddUserToGroup(
		ctx, account314, "devs", "bob", backendtest.GroupGrant(ctx, t, a, account314, "devs"),
	); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	d.mu.Lock()
	d.race = membershipAttempts
	d.mu.Unlock()
	err := a.RemoveUserFromGroup(ctx, account314, "devs", "bob", backendtest.GroupGrant(ctx, t, a, account314, "devs"))
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("RemoveUserFromGroup: %v", err)
	}
	_, us, err := a.GetGroup(ctx, account314, "devs", backendtest.GroupGrant(ctx, t, a, account314, "devs"))
	if err != nil || len(us) != 2 {
		t.Fatalf("members %+v %v", us, err)
	}
}

// vws-iam cannot rename: a new name answers Unimplemented (InvalidAction)
// after the name rules and the lookup, and sends no update.
func TestRenameIsNotServedOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	err := a.UpdateUser(ctx, account314, "alice", "", "carol", backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if resource.CodeOf(err) != resource.CodeUnimplemented || !strings.Contains(err.Error(), "cannot rename") {
		t.Errorf("UpdateUser rename: %v", err)
	}
	if err := a.UpdateUser(
		ctx, account314, "ghost", "", "carol", backendtest.UserGrant(ctx, t, a, account314, "ghost"),
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("UpdateUser rename of a missing user: %v", err)
	}
	err = a.UpdateUser(ctx, account314, "alice", "", "root", backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("UpdateUser rename to root: %v", err)
	}
	if err := a.UpdateGroup(
		ctx, account314, "devs", "", "ops", backendtest.GroupGrant(ctx, t, a, account314, "devs"),
	); resource.CodeOf(err) != resource.CodeUnimplemented {
		t.Errorf("UpdateGroup rename: %v", err)
	}
	if err := a.UpdateGroup(
		ctx, account314, "ghost", "", "ops", backendtest.GroupGrant(ctx, t, a, account314, "ghost"),
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("UpdateGroup rename of a missing group: %v", err)
	}
	if n := len(d.sent("UpdateUser")); n != 0 {
		t.Errorf("%d UpdateUser calls", n)
	}
	if n := len(d.sent("UpdateGroup")); n != 1 { // the seed's AddUserToGroup
		t.Errorf("%d UpdateGroup calls", n)
	}
}

// The List calls read every vws-iam page, and vws-iam's case folding is
// kept: a lookup in another case answers with the stored name.
func TestListsReadEveryPageAndKeepTheStoredName(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	for _, n := range []string{"carol", "dave", "erin"} {
		if _, err := a.CreateUser(ctx, account314, n, "/"); err != nil {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	d.maxPage = 2
	d.mu.Unlock()
	us, err := a.ListUsers(ctx, account314, "")
	if err != nil || len(us) != 5 || us[0].Name != "alice" || us[4].Name != "erin" {
		t.Fatalf("ListUsers: %+v %v", us, err)
	}
	if n := len(d.sent("ListUsers")); n != 3 {
		t.Errorf("%d ListUsers pages, want 3", n)
	}
	r := d.sent("ListUsers")[0].(*iamv1.ListUsersRequest)
	if r.GetPageSize() != listPageSize || r.GetParent() != "projects/123456789012" {
		t.Errorf("ListUsers sent %v", r)
	}
	u, err := a.GetUser(ctx, account314, "ALICE", backendtest.UserGrant(ctx, t, a, account314, "ALICE"))
	if err != nil || u.Name != "alice" || u.ARN != "arn:vws:iam::123456789012:user/ops/alice" {
		t.Errorf("GetUser ALICE: %+v %v", u, err)
	}
	if _, err := a.CreateUser(ctx, account314, "Alice", "/"); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Errorf("CreateUser Alice: %v", err)
	}
}

var (
	spansOnce sync.Once
	spans     *tracetest.SpanRecorder
)

func spanRecorder() *tracetest.SpanRecorder {
	spansOnce.Do(func() {
		spans = tracetest.NewSpanRecorder()
		otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	})
	return spans
}

// Each user and group call leaves a client span with its outcome, and each
// change one structured log record with names only.
func TestUserAndGroupCallsAreTracedAndLogged(t *testing.T) {
	rec := spanRecorder()
	var buf bytes.Buffer
	c, _ := dirHarness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	a := STSAdmin{Client: c}
	ctx := t.Context()
	if _, err := a.CreateUser(ctx, account314, "carol", "/qa/"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateUser(ctx, account314, "carol", "/qa/"); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatal(err)
	}
	if _, err := a.ListUsers(ctx, account314, ""); err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, s := range rec.Ended() {
		if !strings.HasPrefix(s.Name(), "vws-iam ") {
			continue
		}
		for _, kv := range s.Attributes() {
			if kv.Key == "vws.iam.outcome" {
				outcomes = append(outcomes, s.Name()+"="+kv.Value.AsString())
			}
		}
	}
	got := strings.Join(outcomes, " ")
	for _, want := range []string{"vws-iam CreateUser=ok", "vws-iam CreateUser=AlreadyExists", "vws-iam ListUsers=ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("spans %q lack %q", got, want)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log records: %q", lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["action"] != "CreateUser" || first["user_name"] != "carol" || first["outcome"] != "ok" ||
		first["account"] != "123456789012" {
		t.Errorf("log record %v", first)
	}
	if !strings.Contains(lines[1], `"outcome":"AlreadyExists"`) {
		t.Errorf("log record %s", lines[1])
	}
}

var _ iam.Directory = STSAdmin{}
