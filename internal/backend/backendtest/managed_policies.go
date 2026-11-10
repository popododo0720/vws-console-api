package backendtest

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMManagedPolicies runs the #574 contract of managed policy CreatePolicy,
// GetPolicy, ListPolicies and DeletePolicy, which the in-memory fake and the
// vws-iam client must answer alike, AWS error codes included: a missing
// policy is NoSuchEntity, a malformed document MalformedPolicyDocument, a
// taken name EntityAlreadyExists and deleting an attached policy
// DeleteConflict.
func IAMManagedPolicies(t *testing.T, newAdmin func(t *testing.T) iam.Directory) {
	t.Helper()
	ctx := context.Background()
	acct := iamAccount()
	doc := identityDoc("*")
	missing := arnPrefix + "policy/team/Nope"

	t.Run("CreateGetList", func(t *testing.T) {
		a := newAdmin(t)
		p, err := a.CreatePolicy(ctx, acct, "Ops", "/team/", doc, "ops access")
		wantOK(t, "CreatePolicy", err)
		if p.ARN != arnPrefix+"policy/team/Ops" || p.Name != "Ops" || p.Path != "/team/" ||
			p.DefaultVersion != "v1" || p.Description != "ops access" || !strings.HasPrefix(p.ID, "ANPA") ||
			p.Created.IsZero() {
			t.Fatalf("CreatePolicy = %+v", p)
		}
		_, err = a.CreatePolicy(ctx, acct, "ReadOnly", "", doc, "")
		wantOK(t, "CreatePolicy ReadOnly", err)
		got, err := a.GetPolicy(ctx, acct, p.ARN)
		wantOK(t, "GetPolicy", err)
		if got.ARN != p.ARN || got.ID != p.ID || got.Description != p.Description || got.AttachmentCount != 0 {
			t.Fatalf("GetPolicy = %+v, created %+v", got, p)
		}
		for prefix, want := range map[string][]string{"": {"Ops", "ReadOnly"}, "/team/": {"Ops"}, "/eng/": {}} {
			ps, err := a.ListPolicies(ctx, acct, prefix)
			wantOK(t, "ListPolicies "+prefix, err)
			names := []string{}
			for _, p := range ps {
				names = append(names, p.Name)
			}
			wantNames(t, "ListPolicies "+prefix, names, want)
		}
	})

	t.Run("Errors", func(t *testing.T) {
		a := newAdmin(t)
		p, err := a.CreatePolicy(ctx, acct, "Ops", "/team/", doc, "")
		wantOK(t, "CreatePolicy", err)
		_, err = a.CreatePolicy(ctx, acct, "Ops", "/", doc, "")
		wantErr(t, "CreatePolicy taken", err, resource.CodeAlreadyExists,
			"A policy called Ops already exists. Duplicate names are not allowed.")
		_, err = a.CreatePolicy(ctx, acct, "Bad", "/", `{"Version":"2012-10-17","Statement":`, "")
		wantErr(t, "CreatePolicy malformed", err, resource.CodeInvalidArgument, "")
		if f := resource.AsError(err).Field; f != "PolicyDocument" {
			t.Fatalf("CreatePolicy malformed: field %q, want PolicyDocument (MalformedPolicyDocument)", f)
		}
		_, err = a.CreatePolicy(ctx, acct, "bad name!", "/", doc, "")
		wantErr(t, "CreatePolicy bad name", err, resource.CodeInvalidArgument, "")
		_, err = a.GetPolicy(ctx, acct, missing)
		wantErr(t, "GetPolicy missing", err, resource.CodeNotFound, resource.AsError(iam.PolicyNotAttachable(missing)).Message)
		wrongPath := arnPrefix + "policy/Ops"
		_, err = a.GetPolicy(ctx, acct, wrongPath)
		wantErr(t, "GetPolicy wrong path", err, resource.CodeNotFound, "")
		wantErr(t, "DeletePolicy wrong path", a.DeletePolicy(ctx, acct, wrongPath), resource.CodeNotFound, "")
		wantErr(t, "DeletePolicy missing", a.DeletePolicy(ctx, acct, missing), resource.CodeNotFound, "")
		if _, err := a.GetPolicy(ctx, acct, p.ARN); err != nil {
			t.Fatalf("a refused delete removed the policy: %v", err)
		}
	})

	t.Run("DeleteAttached", func(t *testing.T) {
		a := newAdmin(t)
		seedIAM(ctx, t, a)
		p, err := a.CreatePolicy(ctx, acct, "Ops", "/team/", doc, "")
		wantOK(t, "CreatePolicy", err)
		bob := Grant(ctx, t, arnPrefix+"user/eng/bob")
		wantOK(t, "AttachPolicy", a.AttachPolicy(ctx, acct, iam.EntityUser, "bob", p.ARN, bob))
		got, err := a.GetPolicy(ctx, acct, p.ARN)
		wantOK(t, "GetPolicy", err)
		if got.AttachmentCount != 1 {
			t.Fatalf("AttachmentCount = %d, want 1", got.AttachmentCount)
		}
		wantErr(t, "DeletePolicy attached", a.DeletePolicy(ctx, acct, p.ARN), resource.CodeConflict, "")
		wantOK(t, "DetachPolicy", a.DetachPolicy(ctx, acct, iam.EntityUser, "bob", p.ARN, bob))
		wantOK(t, "DeletePolicy", a.DeletePolicy(ctx, acct, p.ARN))
		_, err = a.GetPolicy(ctx, acct, p.ARN)
		wantErr(t, "GetPolicy deleted", err, resource.CodeNotFound, "")
		ps, err := a.ListPolicies(ctx, acct, "")
		wantOK(t, "ListPolicies", err)
		if len(ps) != 0 {
			t.Fatalf("ListPolicies after delete = %+v", ps)
		}
	})
}
