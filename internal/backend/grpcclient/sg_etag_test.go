package grpcclient

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestConcurrentAuthorizesKeepEveryRule proves the authorize read, union and
// write is compare-and-swap on the group etag. The loopback refuses a stale
// etag, so a client that does not reread and retry loses rules.
func TestConcurrentAuthorizesKeepEveryRule(t *testing.T) {
	set, scope, group := securityGroupForTest(t)
	ctx := t.Context()
	const writers = 8
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{
				Scope: scope, Key: fmt.Sprintf("k-auth-%d", i), Fingerprint: fmt.Sprintf("fp-auth-%d", i),
			}, resource.AuthorizeSecurityGroupIngressRequest{
				ID: group,
				Rule: resource.IngressRule{
					Protocol: "tcp", FromPort: 1000 + i, ToPort: 1000 + i, Cidr: "10.0.0.0/16",
				},
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	page, err := set.Network.DescribeSecurityGroups(ctx, scope, resource.SecurityGroupQuery{
		IDs: []resource.SecurityGroupID{group}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(page.Items[0].Rules); got != writers {
		t.Fatalf("kept %d of %d rules: %+v", got, writers, page.Items[0].Rules)
	}
}

// TestDuplicateRuleIsDuplicatePermission proves a second identical authorize
// is InvalidPermission.Duplicate, not InvalidGroup.Duplicate (#272).
func TestDuplicateRuleIsDuplicatePermission(t *testing.T) {
	set, scope, group := securityGroupForTest(t)
	ctx := t.Context()
	rule := resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"}
	if _, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{
		Scope: scope, Key: "k-auth", Fingerprint: "fp-auth",
	}, resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rule: rule}); err != nil {
		t.Fatal(err)
	}
	_, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{
		Scope: scope, Key: "k-auth-again", Fingerprint: "fp-auth-again",
	}, resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rule: rule})
	if !resource.IsDuplicatePermission(err) {
		t.Fatalf("duplicate rule = %v, want a duplicate permission", err)
	}
	if resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("duplicate rule code = %v", resource.CodeOf(err))
	}
}

// TestMissingRuleIsPermissionNotFound proves revoke reads the group and
// answers a rule it does not hold as InvalidPermission.NotFound (#272).
func TestMissingRuleIsPermissionNotFound(t *testing.T) {
	set, scope, group := securityGroupForTest(t)
	_, err := set.Network.RevokeSecurityGroupIngress(t.Context(), backend.Mutation{
		Scope: scope, Key: "k-revoke", Fingerprint: "fp-revoke",
	}, resource.RevokeSecurityGroupIngressRequest{
		ID: group,
		Rule: resource.IngressRule{
			Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16",
		},
	})
	if !resource.IsPermissionNotFound(err) {
		t.Fatalf("missing rule = %v, want a missing permission", err)
	}
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing rule code = %v", resource.CodeOf(err))
	}
}

// TestSameRequestRetriesTheFirstOperation proves a token retry replays the
// operation instead of answering Duplicate or NotFound (#272).
func TestSameRequestRetriesTheFirstOperation(t *testing.T) {
	set, scope, group := securityGroupForTest(t)
	ctx := t.Context()
	rule := resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"}
	auth := backend.Mutation{Scope: scope, Key: "k-auth", Fingerprint: "fp-auth"}
	first, err := set.Network.AuthorizeSecurityGroupIngress(ctx, auth,
		resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	again, err := set.Network.AuthorizeSecurityGroupIngress(ctx, auth,
		resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rule: rule})
	if err != nil || again.Operation.ID != first.Operation.ID || len(again.Items[0].Rules) != 1 {
		t.Fatalf("authorize retry: %v %+v", err, again)
	}
	revoke := backend.Mutation{Scope: scope, Key: "k-revoke", Fingerprint: "fp-revoke"}
	revoked, err := set.Network.RevokeSecurityGroupIngress(ctx, revoke,
		resource.RevokeSecurityGroupIngressRequest{ID: group, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := set.Network.RevokeSecurityGroupIngress(ctx, revoke,
		resource.RevokeSecurityGroupIngressRequest{ID: group, Rule: rule})
	if err != nil || replayed.Operation.ID != revoked.Operation.ID || len(replayed.Items[0].Rules) != 0 {
		t.Fatalf("revoke retry: %v %+v", err, replayed)
	}
}

// TestConcurrentRevokesKeepNoRule proves a stale etag reread and retry does
// not resurrect or keep a revoked rule.
func TestConcurrentRevokesKeepNoRule(t *testing.T) {
	set, scope, group := securityGroupForTest(t)
	ctx := t.Context()
	const writers = 8
	rules := make([]resource.IngressRule, 0, writers)
	for i := range writers {
		rules = append(rules, resource.IngressRule{
			Protocol: "tcp", FromPort: 2000 + i, ToPort: 2000 + i, Cidr: "10.0.0.0/16",
		})
		if _, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{
			Scope: scope, Key: fmt.Sprintf("k-open-%d", i), Fingerprint: fmt.Sprintf("fp-open-%d", i),
		}, resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rule: rules[i]}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = set.Network.RevokeSecurityGroupIngress(ctx, backend.Mutation{
				Scope: scope, Key: fmt.Sprintf("k-close-%d", i), Fingerprint: fmt.Sprintf("fp-close-%d", i),
			}, resource.RevokeSecurityGroupIngressRequest{ID: group, Rule: rules[i]})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	page, err := set.Network.DescribeSecurityGroups(ctx, scope, resource.SecurityGroupQuery{
		IDs: []resource.SecurityGroupID{group}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(page.Items[0].Rules); got != 0 {
		t.Fatalf("kept %d of %d rules: %+v", got, writers, page.Items[0].Rules)
	}
}

func securityGroupForTest(t *testing.T) (backend.Set, backend.Scope, resource.SecurityGroupID) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}})
	set := dialLoopback(t, world, now)()
	ctx := t.Context()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	vpc, err := set.Network.CreateVpc(ctx, backend.Mutation{
		Scope: scope, Key: "k-vpc", Fingerprint: "fp-vpc",
	}, resource.CreateVpcRequest{
		Cidr: "10.8.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: scope, Key: "k-sg", Fingerprint: "fp-sg",
	}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: vpc.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return set, scope, group.Items[0].ID
}
