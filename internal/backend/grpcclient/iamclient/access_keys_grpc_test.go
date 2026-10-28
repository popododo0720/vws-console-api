package iamclient

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #314 bundle 2: the access key requests carry the vws-iam resource names
// and a UUID request_id. DeleteAccessKey sends no etag: vws-iam bumps a
// key's version each time it is used, so a read etag would go stale.
func TestAccessKeyRequestsOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	k, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateAccessKey(
		ctx, account314, "bob", k.AccessKeyID, iam.AccessKeyInactive,
		backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListAccessKeys(
		ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteAccessKey(
		ctx, account314, "bob", k.AccessKeyID, backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	ck := d.sent("CreateAccessKey")
	if len(ck) != 1 || ck[0].(*iamv1.CreateAccessKeyRequest).GetParent() != "projects/123456789012/users/bob" ||
		!uuidV4.MatchString(ck[0].(*iamv1.CreateAccessKeyRequest).GetRequestId()) {
		t.Errorf("CreateAccessKey requests %v", ck)
	}
	lk := d.sent("ListAccessKeys")
	if len(lk) != 1 || lk[0].(*iamv1.ListAccessKeysRequest).GetParent() != "projects/123456789012/users/bob" {
		t.Errorf("ListAccessKeys requests %v", lk)
	}
	uk := d.sent("UpdateAccessKey")
	if len(uk) != 1 {
		t.Fatalf("UpdateAccessKey requests %v", uk)
	}
	upd := uk[0].(*iamv1.UpdateAccessKeyRequest)
	if upd.GetAccessKey().GetName() != "projects/123456789012/users/bob/accessKeys/"+k.AccessKeyID ||
		upd.GetAccessKey().GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE ||
		!slices.Equal(upd.GetUpdateMask().GetPaths(), []string{"spec.state"}) ||
		!uuidV4.MatchString(upd.GetRequestId()) || upd.GetAccessKey().GetEtag() != "" || upd.GetAllowMissing() {
		t.Errorf("UpdateAccessKey request %v", upd)
	}
	dk := d.sent("DeleteAccessKey")
	if len(dk) != 1 {
		t.Fatalf("DeleteAccessKey requests %v", dk)
	}
	del := dk[0].(*iamv1.DeleteAccessKeyRequest)
	if del.GetName() != "projects/123456789012/users/bob/accessKeys/"+k.AccessKeyID ||
		!uuidV4.MatchString(del.GetRequestId()) || del.GetEtag() != "" || del.GetAllowMissing() {
		t.Errorf("DeleteAccessKey request %v", del)
	}
}

// CreateAccessKey is never retried: vws-iam does not replay it, so a retry
// after a lost response would make a second key and a second secret. An
// UNAVAILABLE answer is 503 after exactly one attempt. DeleteAccessKey is
// replayed by request_id, so it is retried.
func TestCreateAccessKeyIsNotRetriedOverGRPC(t *testing.T) {
	ctx := t.Context()
	for _, after := range []bool{false, true} {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		if after {
			d.failAfter["CreateAccessKey"] = 1
		} else {
			d.failBefore["CreateAccessKey"] = 1
		}
		d.mu.Unlock()
		_, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
		if resource.CodeOf(err) != resource.CodeUnavailable {
			t.Errorf("after=%v: %v, want Unavailable", after, err)
		}
		if n := len(d.sent("CreateAccessKey")); n != 1 {
			t.Errorf("after=%v: %d CreateAccessKey attempts, want 1", after, n)
		}
	}
	a, d := seeded(ctx, t)
	k, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.failAfter["DeleteAccessKey"] = 1
	d.mu.Unlock()
	if err := a.DeleteAccessKey(
		ctx, account314, "bob", k.AccessKeyID, backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatalf("DeleteAccessKey with a lost response: %v", err)
	}
	dk := d.sent("DeleteAccessKey")
	if len(dk) != 2 || dk[0].(*iamv1.DeleteAccessKeyRequest).GetRequestId() !=
		dk[1].(*iamv1.DeleteAccessKeyRequest).GetRequestId() {
		t.Errorf("DeleteAccessKey attempts %v, want 2 with one request_id", dk)
	}
}

// UpdateAccessKey is replayed by request_id, so a lost response is retried
// with the same request_id instead of flipping the state twice.
func TestUpdateAccessKeyIsRetriedOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	k, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.failAfter["UpdateAccessKey"] = 1
	d.mu.Unlock()
	if err := a.UpdateAccessKey(
		ctx, account314, "bob", k.AccessKeyID, iam.AccessKeyInactive,
		backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatalf("UpdateAccessKey with a lost response: %v", err)
	}
	uk := d.sent("UpdateAccessKey")
	if len(uk) != 2 || uk[0].(*iamv1.UpdateAccessKeyRequest).GetRequestId() !=
		uk[1].(*iamv1.UpdateAccessKeyRequest).GetRequestId() {
		t.Errorf("UpdateAccessKey attempts %v, want 2 with one request_id", uk)
	}
}

// A user moved after UpdateAccessKey read it is never reported as a
// successful change under the old ARN: the key request carries no path or
// parent version, so the client reads the user again after the call and
// answers ConcurrentModification instead.
func TestUpdateAccessKeyFailsClosedWhenTheUserMovesDuringTheCall(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	grant := backendtest.UserGrant(ctx, t, a, account314, "bob")
	k, err := a.CreateAccessKey(ctx, account314, "bob", grant)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.keyRace, d.keyRacePath = 1, "/denied/"
	d.mu.Unlock()
	err = a.UpdateAccessKey(ctx, account314, "bob", k.AccessKeyID, iam.AccessKeyInactive, grant)
	if !iam.IsChanged(err) || resource.AsError(err).Message != iam.UserChanged {
		t.Fatalf("UpdateAccessKey of a user moved during the call: %v", err)
	}
	if n := len(d.sent("UpdateAccessKey")); n != 1 {
		t.Errorf("%d UpdateAccessKey calls, want 1 (the move lands after the lookup)", n)
	}
}

// The state vws-iam reports maps to AWS Status Active or Inactive. Any other
// state, or a malformed CreateAccessKey answer, is an internal error that
// never carries the secret.
func TestAccessKeyStatusAndShapeOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	k, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.keyState = iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE
	d.mu.Unlock()
	ks, err := a.ListAccessKeys(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil || len(ks) != 1 || ks[0].Status != "Inactive" || ks[0].AccessKeyID != k.AccessKeyID {
		t.Fatalf("inactive key listed as %+v: %v", ks, err)
	}
	d.mu.Lock()
	d.keyState = iamv1.AccessKeyState(7)
	d.mu.Unlock()
	if _, err := a.ListAccessKeys(
		ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("state 7: %v, want Internal", err)
	}
	if _, err := a.CreateAccessKey(
		ctx, account314, "alice", backendtest.UserGrant(ctx, t, a, account314, "alice"),
	); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("create answered with state 7: %v, want Internal", err)
	}
	d.mu.Lock()
	d.keyState = iamv1.AccessKeyState_ACCESS_KEY_STATE_UNSPECIFIED
	short := "s3cr3t-too-short-for-vws-iam"
	d.createSecret = &short
	d.mu.Unlock()
	_, err = a.CreateAccessKey(ctx, account314, "alice", backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if resource.CodeOf(err) != resource.CodeInternal || strings.Contains(err.Error(), short) {
		t.Fatalf("short secret: %v, want Internal without the secret", err)
	}
}

// The secret appears only in the CreateAccessKey result: never in a span, a
// log record or an error, and the client keeps no copy.
func TestAccessKeySecretIsNeverLoggedOrTraced(t *testing.T) {
	rec := spanRecorder()
	before := len(rec.Ended())
	var buf bytes.Buffer
	c, d := dirHarness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	a := STSAdmin{Client: c}
	ctx := t.Context()
	if _, err := a.CreateUser(ctx, account314, "bob", "/eng/"); err != nil {
		t.Fatal(err)
	}
	k, err := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Secret) != 40 {
		t.Fatalf("secret of %d characters", len(k.Secret))
	}
	if err := a.UpdateAccessKey(
		ctx, account314, "bob", k.AccessKeyID, iam.AccessKeyInactive,
		backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListAccessKeys(
		ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.failAfter["CreateAccessKey"] = 1
	d.mu.Unlock()
	_, lost := a.CreateAccessKey(ctx, account314, "bob", backendtest.UserGrant(ctx, t, a, account314, "bob"))
	d.mu.Lock()
	leaked := "s3cr3t-0123456789-must-never-be-logged"
	d.createSecret = &leaked
	d.mu.Unlock()
	_, short := a.CreateAccessKey(ctx, account314, "alice", backendtest.UserGrant(ctx, t, a, account314, "alice"))
	if err := a.DeleteAccessKey(
		ctx, account314, "bob", k.AccessKeyID, backendtest.UserGrant(ctx, t, a, account314, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	seen.WriteString(buf.String())
	for _, err := range []error{lost, short} {
		if err != nil {
			seen.WriteString(err.Error())
		}
	}
	var actions []string
	for _, s := range rec.Ended()[before:] {
		seen.WriteString(s.Name() + s.Status().Description)
		for _, kv := range s.Attributes() {
			seen.WriteString(string(kv.Key) + "=" + kv.Value.String())
			if kv.Key == "vws.iam.action" {
				actions = append(actions, kv.Value.AsString())
			}
		}
		for _, ev := range s.Events() {
			seen.WriteString(ev.Name)
			for _, kv := range ev.Attributes {
				seen.WriteString(kv.Value.String())
			}
		}
	}
	for _, secret := range []string{k.Secret, leaked} {
		if strings.Contains(seen.String(), secret) {
			t.Errorf("a secret appears in a span, log record or error: %s", seen.String())
		}
	}
	for _, want := range []string{"CreateAccessKey", "ListAccessKeys", "UpdateAccessKey", "DeleteAccessKey"} {
		if !strings.Contains(strings.Join(actions, " "), want) {
			t.Errorf("no %s span in %q", want, actions)
		}
	}
	if !strings.Contains(buf.String(), `"action":"CreateAccessKey"`) ||
		!strings.Contains(buf.String(), `"access_key_id":"`+k.AccessKeyID+`"`) {
		t.Errorf("no structured CreateAccessKey record naming the key id: %s", buf.String())
	}
}

// Bundle 2 of #314 through the Query surface over gRPC: the AWS shapes,
// limits, codes and paging, and ConcurrentModification when the user moves
// between the authorization and the call.
func TestAccessKeyActionsThroughTheQuerySurfaceOverGRPC(t *testing.T) {
	h, _, d := dirQueryHarness(t)
	create := url.Values{"Action": {"CreateAccessKey"}, "UserName": {"alice"}}
	res := queryCall(t, h, create)
	expect(t, res, http.StatusOK, "<CreateAccessKeyResponse", "<UserName>alice</UserName>",
		"<Status>Active</Status>", "<CreateDate>")
	secret := regexp.MustCompile(`<SecretAccessKey>([^<]{40})</SecretAccessKey>`).FindStringSubmatch(res.Body.String())
	id1 := regexp.MustCompile(`<AccessKeyId>(AKIA[A-Z2-7]{16})</AccessKeyId>`).FindStringSubmatch(res.Body.String())
	if secret == nil || id1 == nil {
		t.Fatalf("create: %s", res.Body.String())
	}
	res = queryCall(t, h, create)
	expect(t, res, http.StatusOK)
	id2 := regexp.MustCompile(`<AccessKeyId>(AKIA[A-Z2-7]{16})</AccessKeyId>`).FindStringSubmatch(res.Body.String())
	expect(t, queryCall(t, h, create), http.StatusConflict,
		"<Code>LimitExceeded</Code>", "Cannot exceed quota for AccessKeysPerUser: 2")
	first, second := id1[1], id2[1]
	if second < first {
		first, second = second, first
	}
	list := url.Values{"Action": {"ListAccessKeys"}, "UserName": {"alice"}, "MaxItems": {"1"}}
	res = queryCall(t, h, list)
	expect(t, res, http.StatusOK, "<AccessKeyId>"+first+"</AccessKeyId>", "<IsTruncated>true</IsTruncated>",
		"<UserName>alice</UserName>")
	if strings.Contains(res.Body.String(), "SecretAccessKey") || strings.Contains(res.Body.String(), secret[1]) {
		t.Errorf("a listing carries a secret: %s", res.Body.String())
	}
	marker := regexp.MustCompile(`<Marker>([^<]+)</Marker>`).FindStringSubmatch(res.Body.String())
	if marker == nil {
		t.Fatalf("no marker: %s", res.Body.String())
	}
	list.Set("Marker", marker[1])
	expect(t, queryCall(t, h, list), http.StatusOK, "<AccessKeyId>"+second+"</AccessKeyId>",
		"<IsTruncated>false</IsTruncated>")
	del := url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {first}}
	expect(t, queryCall(t, h, del), http.StatusOK, "<DeleteAccessKeyResponse")
	expect(t, queryCall(t, h, del), http.StatusNotFound, "<Code>NoSuchEntity</Code>",
		"The Access Key with name "+first+" cannot be found.")
	del.Set("AccessKeyId", "not-a-key-id-00000")
	expect(t, queryCall(t, h, del), http.StatusBadRequest, "<Code>ValidationError</Code>")
	expect(t, queryCall(t, h, url.Values{"Action": {"ListAccessKeys"}, "UserName": {"ghost"}}),
		http.StatusNotFound, "<Code>NoSuchEntity</Code>", "The user with name ghost cannot be found.")
	update := func(key, status string) url.Values {
		return url.Values{"Action": {"UpdateAccessKey"}, "UserName": {"alice"}, "AccessKeyId": {key}, "Status": {status}}
	}
	expect(t, queryCall(t, h, update(second, "Inactive")), http.StatusOK, "<UpdateAccessKeyResponse")
	expect(t, queryCall(t, h, list), http.StatusOK, "<AccessKeyId>"+second+"</AccessKeyId>", "<Status>Inactive</Status>")
	expect(t, queryCall(t, h, update(second, "Active")), http.StatusOK)
	expect(t, queryCall(t, h, list), http.StatusOK, "<Status>Active</Status>")
	expect(t, queryCall(t, h, update(second, "Paused")), http.StatusBadRequest,
		"<Code>ValidationError</Code>", "enum value set: [Active, Inactive]")
	expect(t, queryCall(t, h, update(second, "")), http.StatusBadRequest,
		"<Code>ValidationError</Code>", "Member must not be null")
	expect(t, queryCall(t, h, update("AKIAAAAAAAAAAAAAAAAA", "Active")), http.StatusNotFound,
		"<Code>NoSuchEntity</Code>")
	expect(t, queryCall(t, h, url.Values{"Action": {"DeleteUser"}, "UserName": {"alice"}}),
		http.StatusConflict, "<Code>DeleteConflict</Code>")
	if n := len(d.sent("DeleteAccessKey")); n != 2 {
		t.Errorf("%d DeleteAccessKey calls, want 2 (the malformed id is refused first)", n)
	}
	if n := len(d.sent("UpdateAccessKey")); n != 3 {
		t.Errorf("%d UpdateAccessKey calls, want 3 (the invalid status and missing key are refused first)", n)
	}
}

func TestAccessKeyCallsActOnTheAuthorizedARNOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		name      string
		form      func(key string) url.Values
		unchanged func(t *testing.T, d *directory, body string)
	}{
		{
			"CreateAccessKey", func(string) url.Values {
				return url.Values{"Action": {"CreateAccessKey"}, "UserName": {"erin"}}
			},
			func(t *testing.T, d *directory, _ string) {
				t.Helper()
				if n := len(d.sent("CreateAccessKey")); n != 1 {
					t.Errorf("%d CreateAccessKey calls, want only the seed", n)
				}
			},
		},
		{
			"ListAccessKeys", func(string) url.Values {
				return url.Values{"Action": {"ListAccessKeys"}, "UserName": {"erin"}}
			},
			func(t *testing.T, _ *directory, body string) {
				t.Helper()
				if strings.Contains(body, "AKIA") {
					t.Errorf("a key was listed: %s", body)
				}
			},
		},
		{
			"UpdateAccessKey", func(key string) url.Values {
				return url.Values{
					"Action": {"UpdateAccessKey"}, "UserName": {"erin"}, "AccessKeyId": {key}, "Status": {"Inactive"},
				}
			},
			func(t *testing.T, d *directory, _ string) {
				t.Helper()
				if n := len(d.sent("UpdateAccessKey")); n != 0 {
					t.Errorf("%d UpdateAccessKey calls reached vws-iam", n)
				}
			},
		},
		{
			"DeleteAccessKey", func(key string) url.Values {
				return url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"erin"}, "AccessKeyId": {key}}
			},
			func(t *testing.T, d *directory, _ string) {
				t.Helper()
				if n := len(d.sent("DeleteAccessKey")); n != 0 {
					t.Errorf("%d DeleteAccessKey calls reached vws-iam", n)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mover := &movingAdmin{tb: t, user: "erin"}
			h, _, d := dirQueryHarnessWith(t, func(a iam.Directory) iam.Directory {
				mover.Directory = a
				return mover
			})
			if _, err := mover.CreateUser(t.Context(), account314, "erin", "/ops/"); err != nil {
				t.Fatal(err)
			}
			k, err := mover.CreateAccessKey(
				t.Context(), account314, "erin", backendtest.UserGrant(t.Context(), t, mover.Directory, account314, "erin"),
			)
			if err != nil {
				t.Fatal(err)
			}
			res := queryCall(t, h, tc.form(k.AccessKeyID))
			tc.unchanged(t, d, res.Body.String())
			expect(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
		})
	}
}
