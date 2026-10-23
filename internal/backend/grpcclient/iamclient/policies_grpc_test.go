package iamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const policyDoc314 = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

// policyWrites are the UpdateUser and UpdateGroup requests on a policy field.
func policyWrites(d *directory) []proto.Message {
	var out []proto.Message
	for _, m := range append(d.sent("UpdateUser"), d.sent("UpdateGroup")...) {
		var paths []string
		switch r := m.(type) {
		case *iamv1.UpdateUserRequest:
			paths = r.GetUpdateMask().GetPaths()
		case *iamv1.UpdateGroupRequest:
			paths = r.GetUpdateMask().GetPaths()
		}
		if slices.Contains(paths, "spec.attached_policies") || slices.Contains(paths, "spec.inline_policies") {
			out = append(out, m)
		}
	}
	return out
}

// #314 bundle 3: a policy change writes one policy field of the user or
// group under the etag it read, with a fresh request_id; an attach that is
// already in place and an identical inline document write nothing.
func TestEntityPolicyRequestsOverGRPC(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	ops := d.seedPolicy("Ops", "/team/")
	before, err := a.users.GetUser(ctx, &iamv1.GetUserRequest{Name: "projects/123456789012/users/bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AttachPolicy(ctx, account314, iam.EntityUser, "bob", ops, ""); err != nil {
		t.Fatal(err)
	}
	ws := policyWrites(d)
	if len(ws) != 1 {
		t.Fatalf("%d policy writes, want 1", len(ws))
	}
	w := ws[0].(*iamv1.UpdateUserRequest)
	if !slices.Equal(w.GetUpdateMask().GetPaths(), []string{"spec.attached_policies"}) ||
		w.GetUser().GetEtag() != before.GetEtag() || !uuidV4.MatchString(w.GetRequestId()) ||
		!slices.Equal(w.GetUser().GetSpec().GetAttachedPolicies(), []string{"projects/123456789012/policies/Ops"}) {
		t.Errorf("UpdateUser %v", w)
	}
	if err := a.AttachPolicy(ctx, account314, iam.EntityUser, "bob", ops, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.PutInlinePolicy(ctx, account314, iam.EntityGroup, "devs", "s3", policyDoc314, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.PutInlinePolicy(ctx, account314, iam.EntityGroup, "devs", "ec2", policyDoc314, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.PutInlinePolicy(ctx, account314, iam.EntityGroup, "devs", "ec2", policyDoc314, ""); err != nil {
		t.Fatal(err)
	}
	ws = policyWrites(d)
	if len(ws) != 3 {
		t.Fatalf("%d policy writes, want 3: a repeated attach or put must not write", len(ws))
	}
	g := ws[2].(*iamv1.UpdateGroupRequest)
	if !slices.Equal(g.GetUpdateMask().GetPaths(), []string{"spec.inline_policies"}) ||
		len(g.GetGroup().GetSpec().GetInlinePolicies()) != 2 || g.GetGroup().GetSpec().GetMembers() != nil ||
		g.GetRequestId() == ws[1].(*iamv1.UpdateGroupRequest).GetRequestId() {
		t.Errorf("UpdateGroup %v", g)
	}
}

// A lost response is retried with the same request_id, which vws-iam
// replays; a lost etag race is read again with a new request_id, up to
// membershipAttempts times, and then a retryable 503.
func TestEntityPolicyChangesRetrySafely(t *testing.T) {
	ctx := t.Context()
	t.Run("response lost", func(t *testing.T) {
		a, d := seeded(ctx, t)
		ops := d.seedPolicy("Ops", "/team/")
		d.mu.Lock()
		d.failAfter["UpdateUser"] = 1
		d.mu.Unlock()
		if err := a.AttachPolicy(ctx, account314, iam.EntityUser, "bob", ops, ""); err != nil {
			t.Fatal(err)
		}
		ws := policyWrites(d)
		if len(ws) != 2 ||
			ws[0].(*iamv1.UpdateUserRequest).GetRequestId() != ws[1].(*iamv1.UpdateUserRequest).GetRequestId() {
			t.Fatalf("writes %v, want one request sent twice", ws)
		}
		ps, err := a.ListAttachedPolicies(ctx, account314, iam.EntityUser, "bob", "")
		if err != nil || len(ps) != 1 {
			t.Fatalf("attached %+v %v", ps, err)
		}
	})
	t.Run("lost race", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.policyRace = 1
		d.mu.Unlock()
		if err := a.PutInlinePolicy(ctx, account314, iam.EntityUser, "bob", "s3", policyDoc314, ""); err != nil {
			t.Fatal(err)
		}
		ws := policyWrites(d)
		if len(ws) != 2 ||
			ws[0].(*iamv1.UpdateUserRequest).GetRequestId() == ws[1].(*iamv1.UpdateUserRequest).GetRequestId() ||
			ws[0].(*iamv1.UpdateUserRequest).GetUser().GetEtag() == ws[1].(*iamv1.UpdateUserRequest).GetUser().GetEtag() {
			t.Fatalf("writes %v, want a second request on the new etag", ws)
		}
	})
	t.Run("keeps losing", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.policyRace = membershipAttempts
		d.mu.Unlock()
		err := a.DeleteInlinePolicy(ctx, account314, iam.EntityGroup, "devs", "s3", "")
		if resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("Delete of a missing policy: %v", err)
		}
		err = a.PutInlinePolicy(ctx, account314, iam.EntityGroup, "devs", "s3", policyDoc314, "")
		if resource.CodeOf(err) != resource.CodeUnavailable {
			t.Fatalf("Put: %v, want Unavailable", err)
		}
		if n := len(policyWrites(d)); n != membershipAttempts {
			t.Errorf("%d writes, want %d", n, membershipAttempts)
		}
		ns, err := a.ListInlinePolicies(ctx, account314, iam.EntityGroup, "devs", "")
		if err != nil || len(ns) != 0 {
			t.Fatalf("inline %q %v", ns, err)
		}
	})
	t.Run("moved by the writer that won", func(t *testing.T) {
		a, d := seeded(ctx, t)
		ops := d.seedPolicy("Ops", "/team/")
		d.mu.Lock()
		d.policyRace, d.policyRacePath = 1, "/denied/"
		d.mu.Unlock()
		err := a.AttachPolicy(ctx, account314, iam.EntityUser, "bob", ops, "arn:vws:iam::123456789012:user/eng/bob")
		if !iam.IsChanged(err) {
			t.Fatalf("Attach: %v, want ConcurrentModification", err)
		}
		if n := len(policyWrites(d)); n != 1 {
			t.Errorf("%d writes, want only the one vws-iam refused", n)
		}
	})
	t.Run("vws-iam stays down", func(t *testing.T) {
		a, d := seeded(ctx, t)
		d.mu.Lock()
		d.failBefore["GetGroup"] = 100
		d.mu.Unlock()
		short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := a.ListInlinePolicies(short, account314, iam.EntityGroup, "devs", "")
		if resource.CodeOf(err) != resource.CodeUnavailable || time.Since(start) > 2*time.Second {
			t.Fatalf("ListInlinePolicies: %v after %v", err, time.Since(start))
		}
	})
}

// vws-iam limits the client answers before a call: inline policy names of
// 65 to 128 characters, which AWS allows, and documents vws-iam refuses,
// such as one without Version. A policy vws-iam no longer has is not listed.
func TestEntityPolicyVWSIAMLimits(t *testing.T) {
	ctx := t.Context()
	a, d := seeded(ctx, t)
	long := strings.Repeat("p", 65)
	err := a.PutInlinePolicy(ctx, account314, iam.EntityUser, "bob", long, policyDoc314, "")
	if resource.CodeOf(err) != resource.CodeInvalidArgument || resource.AsError(err).Field != "policyName" ||
		!strings.Contains(err.Error(), "64") {
		t.Fatalf("Put with a 65 character name: %v", err)
	}
	if n := len(policyWrites(d)); n != 0 {
		t.Fatalf("%d writes for a name vws-iam refuses", n)
	}
	noVersion := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	err = a.PutInlinePolicy(ctx, account314, iam.EntityUser, "bob", "nov", noVersion, "")
	if resource.CodeOf(err) != resource.CodeInvalidArgument || resource.AsError(err).Field != "PolicyDocument" {
		t.Fatalf("Put without Version: %v", err)
	}
	gone := d.seedPolicy("Gone", "/")
	kept := d.seedPolicy("Kept", "/")
	for _, p := range []string{gone, kept} {
		if err := a.AttachPolicy(ctx, account314, iam.EntityGroup, "devs", p, ""); err != nil {
			t.Fatal(err)
		}
	}
	d.dropPolicy("Gone")
	ps, err := a.ListAttachedPolicies(ctx, account314, iam.EntityGroup, "devs", "")
	if err != nil || len(ps) != 1 || ps[0].ARN != kept || ps[0].Path != "/" || ps[0].Name != "Kept" {
		t.Fatalf("attached %+v %v", ps, err)
	}
	for _, call := range []func() error{
		func() error { return a.AttachPolicy(ctx, account314, iam.EntityRole, "r", kept, "") },
		func() error { return a.PutInlinePolicy(ctx, account314, iam.EntityRole, "r", "p", policyDoc314, "") },
		func() error { _, err := a.ListInlinePolicies(ctx, account314, iam.EntityRole, "r", ""); return err },
	} {
		if err := call(); resource.CodeOf(err) != resource.CodeUnimplemented {
			t.Errorf("a role policy call: %v, want Unimplemented", err)
		}
	}
}

// Each policy call leaves a span and each change a log record with the
// entity and the policy name or ARN, never the policy document.
func TestEntityPolicyCallsAreTracedAndLoggedWithoutDocuments(t *testing.T) {
	rec := spanRecorder()
	var buf bytes.Buffer
	c, d := dirHarness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	a := STSAdmin{Client: c}
	ctx := t.Context()
	if _, err := a.CreateUser(ctx, account314, "tracy", "/"); err != nil {
		t.Fatal(err)
	}
	ops := d.seedPolicy("Ops", "/team/")
	marker := "arn:vws:s3:::document-marker-314"
	doc := strings.Replace(policyDoc314, `"*"`, `"`+marker+`"`, 1)
	buf.Reset()
	if err := a.PutInlinePolicy(ctx, account314, iam.EntityUser, "tracy", "s3", doc, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetInlinePolicy(ctx, account314, iam.EntityUser, "tracy", "s3", ""); err != nil {
		t.Fatal(err)
	}
	if err := a.AttachPolicy(ctx, account314, iam.EntityUser, "tracy", ops, ""); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(doc, `"Allow"`, `"Maybe"`, 1)
	if err := a.PutInlinePolicy(ctx, account314, iam.EntityUser, "tracy", "bad", bad, ""); err == nil {
		t.Fatal("a malformed document was stored")
	}
	if strings.Contains(buf.String(), "document-marker-314") {
		t.Fatalf("a policy document reached the log: %s", buf.String())
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("log records %q, want one per change", lines)
	}
	var put, attach map[string]any
	if json.Unmarshal([]byte(lines[0]), &put) != nil || json.Unmarshal([]byte(lines[1]), &attach) != nil {
		t.Fatal(lines)
	}
	if put["action"] != "PutUserPolicy" || put["user_name"] != "tracy" || put["policy_name"] != "s3" ||
		put["outcome"] != "ok" || attach["action"] != "AttachUserPolicy" || attach["policy_arn"] != ops {
		t.Errorf("log records %v %v", put, attach)
	}
	seen := map[string]bool{}
	for _, s := range rec.Ended() {
		for _, kv := range s.Attributes() {
			if strings.Contains(kv.Value.String(), "document-marker-314") {
				t.Errorf("span %s carries the document", s.Name())
			}
		}
		seen[s.Name()] = true
	}
	for _, want := range []string{"vws-iam PutUserPolicy", "vws-iam GetUserPolicy", "vws-iam AttachUserPolicy"} {
		if !seen[want] {
			t.Errorf("no span %s", want)
		}
	}
}

// #314 bundle 3: the user and group policy actions over gRPC, through the
// Query surface, with the AWS shapes, codes and the authorized ARN.
func TestEntityPolicyActionsThroughTheQuerySurfaceOverGRPC(t *testing.T) {
	h, _, d := dirQueryHarness(t)
	ops := d.seedPolicy("Ops", "/team/")
	f := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for _, st := range []struct {
		form   url.Values
		status int
		parts  []string
	}{
		{
			f("Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", ops), 200,
			[]string{"<AttachGroupPolicyResponse"},
		},
		{f("Action", "ListAttachedGroupPolicies", "GroupName", "devs", "PathPrefix", "/team/"), 200, []string{
			"<AttachedPolicies><member><PolicyName>Ops</PolicyName><PolicyArn>" + ops +
				"</PolicyArn></member></AttachedPolicies>",
			"<IsTruncated>false</IsTruncated>",
		}},
		{
			f("Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", "arn:vws:iam::123456789012:policy/Ops"), 404,
			[]string{"<Code>NoSuchEntity</Code>", "does not exist or is not attachable."},
		},
		{f("Action", "PutUserPolicy", "UserName", "alice", "PolicyName", "s3", "PolicyDocument", policyDoc314), 200, nil},
		{f("Action", "GetUserPolicy", "UserName", "alice", "PolicyName", "s3"), 200, []string{
			"<UserName>alice</UserName>", "<PolicyName>s3</PolicyName>", "<PolicyDocument>%7B%22Version%22%3A%222012-10-17%22",
		}},
		{
			f("Action", "ListUserPolicies", "UserName", "alice"), 200,
			[]string{"<PolicyNames><member>s3</member></PolicyNames>"},
		},
		{
			f("Action", "PutUserPolicy", "UserName", "alice", "PolicyName", "x", "PolicyDocument", `{"Version":"2012-10-17"}`),
			400,
			[]string{"<Code>MalformedPolicyDocument</Code>"},
		},
		{f("Action", "DeleteUser", "UserName", "alice"), 409, []string{"<Code>DeleteConflict</Code>"}},
		{f("Action", "DeleteUserPolicy", "UserName", "alice", "PolicyName", "s3"), 200, nil},
		{
			f("Action", "GetUserPolicy", "UserName", "alice", "PolicyName", "s3"), 404,
			[]string{"<Code>NoSuchEntity</Code>", "The user policy with name s3 cannot be found."},
		},
		{f("Action", "DetachGroupPolicy", "GroupName", "devs", "PolicyArn", ops), 200, nil},
		{
			f("Action", "DetachGroupPolicy", "GroupName", "devs", "PolicyArn", ops), 404,
			[]string{"<Code>NoSuchEntity</Code>", "Policy " + ops + " was not found."},
		},
	} {
		rec := queryCall(t, h, st.form)
		expect(t, rec, st.status, st.parts...)
	}
}

// #314 bundle 3: over gRPC a policy call acts only on the ARN the caller was
// authorized on; an entity moved in between is 409 ConcurrentModification
// and nothing is written.
func TestEntityPolicyCallsActOnTheAuthorizedARNOverGRPC(t *testing.T) {
	for _, tc := range []struct {
		form        url.Values
		group, user string
	}{
		{url.Values{"Action": {"AttachGroupPolicy"}, "GroupName": {"devs"}, "PolicyArn": {"Ops"}}, "devs", ""},
		{
			url.Values{
				"Action": {"PutGroupPolicy"}, "GroupName": {"devs"}, "PolicyName": {"p"},
				"PolicyDocument": {policyDoc314},
			},
			"devs", "",
		},
		{url.Values{"Action": {"ListGroupPolicies"}, "GroupName": {"devs"}}, "devs", ""},
		{url.Values{"Action": {"DetachUserPolicy"}, "UserName": {"erin"}, "PolicyArn": {"Ops"}}, "", "erin"},
		{url.Values{"Action": {"GetUserPolicy"}, "UserName": {"erin"}, "PolicyName": {"keep"}}, "", "erin"},
		{url.Values{"Action": {"DeleteUserPolicy"}, "UserName": {"erin"}, "PolicyName": {"keep"}}, "", "erin"},
		{url.Values{"Action": {"ListAttachedUserPolicies"}, "UserName": {"erin"}}, "", "erin"},
	} {
		t.Run(tc.form.Get("Action"), func(t *testing.T) {
			mover := &movingAdmin{group: tc.group, user: tc.user}
			h, _, d := dirQueryHarnessWith(t, func(a iam.Admin) iam.Admin {
				mover.Admin = a
				return mover
			})
			ctx := t.Context()
			ops := d.seedPolicy("Ops", "/team/")
			if _, err := mover.CreateUser(ctx, account314, "erin", "/ops/"); err != nil {
				t.Fatal(err)
			}
			if err := mover.AttachPolicy(ctx, account314, iam.EntityUser, "erin", ops, ""); err != nil {
				t.Fatal(err)
			}
			if err := mover.PutInlinePolicy(ctx, account314, iam.EntityUser, "erin", "keep", policyDoc314, ""); err != nil {
				t.Fatal(err)
			}
			if tc.form.Has("PolicyArn") {
				tc.form.Set("PolicyArn", ops)
			}
			before := len(policyWrites(d))
			res := queryCall(t, h, tc.form)
			expect(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
			if n := len(policyWrites(d)) - before; n != 0 {
				t.Errorf("%d policy writes reached vws-iam", n)
			}
			if strings.Contains(res.Body.String(), "keep") || strings.Contains(res.Body.String(), "Ops") {
				t.Errorf("a policy was returned: %s", res.Body)
			}
		})
	}
}
