package iamclient

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const mpDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

// #574: a CreatePolicy whose response is lost is retried with the same
// request_id and answered from the stored operation: one policy, no
// EntityAlreadyExists.
func TestCreatePolicyRetryIsIdempotent(t *testing.T) {
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	d.failAfter["CreatePolicy"] = 1
	p, err := a.CreatePolicy(context.Background(), accountID(t), "Ops", "/team/", mpDoc, "")
	if err != nil {
		t.Fatalf("CreatePolicy after a lost response: %v", err)
	}
	calls := d.calls["CreatePolicy"]
	if len(calls) != 2 || len(d.policies) != 1 || p.ARN != "arn:vws:iam::123456789012:policy/team/Ops" {
		t.Fatalf("calls %d, policies %d, policy %+v", len(calls), len(d.policies), p)
	}
}

// #574: a request the fake refuses never reaches vws-iam.
func TestCreatePolicyChecksBeforeSending(t *testing.T) {
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	for _, in := range [][3]string{{"bad name!", "/", mpDoc}, {"Ok", "no-slash", mpDoc}, {"Ok", "/", "{"}} {
		if _, err := a.CreatePolicy(context.Background(), accountID(t), in[0], in[1], in[2], ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("CreatePolicy %q: %v, want InvalidArgument", in, err)
		}
	}
	if n := len(d.calls["CreatePolicy"]); n != 0 {
		t.Fatalf("%d CreatePolicy calls reached vws-iam", n)
	}
}

// #574: ListPolicies reads every page.
func TestListPoliciesReadsEveryPage(t *testing.T) {
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	d.maxPage = 2
	for _, n := range []string{"A", "B", "C", "D", "E"} {
		d.seedPolicy(n, "/")
	}
	ps, err := a.ListPolicies(context.Background(), accountID(t), "")
	if err != nil || len(ps) != 5 || ps[0].Name != "A" || ps[4].Name != "E" {
		t.Fatalf("ListPolicies = %+v, %v", ps, err)
	}
	if n := len(d.calls["ListPolicies"]); n != 3 {
		t.Fatalf("%d ListPolicies calls, want 3 pages", n)
	}
}

// #574: DeletePolicy sends the etag it read with the ARN check, so a policy
// changed in between is ConcurrentModification and stays.
func TestDeletePolicySendsTheReadEtag(t *testing.T) {
	c, d := dirHarness(t)
	a := STSAdmin{Client: c}
	arn := d.seedPolicy("Ops", "/")
	d.onDeletePolicy = func(d *directory) { d.policies["Ops"].version++ }
	err := a.DeletePolicy(context.Background(), accountID(t), arn)
	if e := resource.AsError(err); e.Code != resource.CodeConflict || e.Field != "ConcurrentModification" {
		t.Fatalf("DeletePolicy after a change: %v, want ConcurrentModification", err)
	}
	if d.policies["Ops"] == nil {
		t.Fatal("the changed policy was deleted")
	}
}
