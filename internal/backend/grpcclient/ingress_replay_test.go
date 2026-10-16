package grpcclient

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAuthorizeReplayUsesTheServerOperation(t *testing.T) {
	set := startLoop(t)
	ctx := t.Context()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	vpc, err := set.Network.CreateVpc(ctx, backend.Mutation{
		Scope: scope, Key: "k-vpc-replay", Fingerprint: "fp-vpc-replay",
	}, resource.CreateVpcRequest{Cidr: "10.4.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: scope, Key: "k-sg-replay", Fingerprint: "fp-sg-replay",
	}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: vpc.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group.Items[0].ID, 22, "10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	requestLocal := strings.ReplaceAll(requestUUID("k-auth", "ingress"), "-", "")
	if opened.Operation.ID.Local() == requestLocal {
		t.Fatalf("operation %s is the request uuid", opened.Operation.ID.Local())
	}
	again, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group.Items[0].ID, 22, "10.0.0.0/16")
	if err != nil || again.Operation.ID != opened.Operation.ID || len(again.Items[0].Rules) != 1 {
		t.Fatalf("replay: %v op %s want %s", err, again.Operation.ID, opened.Operation.ID)
	}
}

func TestAuthorizeReplayRejectsADifferentGroup(t *testing.T) {
	set := startLoop(t)
	ctx := t.Context()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	vpc, err := set.Network.CreateVpc(ctx, backend.Mutation{
		Scope: scope, Key: "k-vpc-other", Fingerprint: "fp-vpc-other",
	}, resource.CreateVpcRequest{Cidr: "10.5.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: scope, Key: "k-sg-a", Fingerprint: "fp-sg-a",
	}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: vpc.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: scope, Key: "k-sg-b", Fingerprint: "fp-sg-b",
	}, resource.CreateSecurityGroupRequest{
		Name: "db", VpcID: vpc.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", first.Items[0].ID, 22, "10.0.0.0/16"); err != nil {
		t.Fatal(err)
	}
	changed, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", second.Items[0].ID, 22, "10.0.0.0/16")
	if resource.CodeOf(err) != resource.CodeIdempotencyMismatch || len(changed.Items) != 0 {
		t.Fatalf("other group: %v %+v", err, changed.Items)
	}
	page, err := set.Network.DescribeSecurityGroups(ctx, scope, resource.SecurityGroupQuery{
		IDs: []resource.SecurityGroupID{second.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].Rules) != 0 {
		t.Fatalf("other group rules: %v %+v", err, page.Items)
	}
}

func TestAuthorizeReplayDoesNotRebuildRules(t *testing.T) {
	set, loop := startLoopWorld(t)
	ctx := t.Context()
	account, scope := replayAccount(t)
	group := replayGroup(t, ctx, set, scope, "10.6.0.0/16", "k-vpc-rebuild", "k-sg-rebuild")
	opened, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group, 22, "10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	writes := loop.specUpdateCount()
	id := group.String()
	labels := loop.labelsOf(id)
	for key := range labels {
		if strings.HasPrefix(key, "vws-iop-") {
			delete(labels, key)
		}
	}
	loop.saveGroupLabels(id, labels)
	stored, ok := loop.group(id, account)
	if !ok {
		t.Fatal("missing group")
	}
	stored.Rules = append(stored.Rules, resource.IngressRule{
		Protocol: "tcp", FromPort: 9, ToPort: 9, Cidr: "10.9.0.0/16",
	})
	loop.saveGroup(stored)
	again, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group, 22, "10.0.0.0/16")
	if err != nil || again.Operation.ID != opened.Operation.ID {
		t.Fatalf("replay: %v op %s want %s", err, again.Operation.ID, opened.Operation.ID)
	}
	if got := loop.specUpdateCount(); got != writes {
		t.Fatalf("replay rewrote rules (%d spec updates, was %d)", got, writes)
	}
	held, ok := loop.group(id, account)
	if !ok || !rulePort(held.Rules, 9) {
		t.Fatalf("replay dropped the concurrent rule %+v", held.Rules)
	}
}

func TestAuthorizeRetriesAStaleGroup(t *testing.T) {
	set, loop := startLoopWorld(t)
	loop.clash = 1
	ctx := t.Context()
	_, scope := replayAccount(t)
	group := replayGroup(t, ctx, set, scope, "10.7.0.0/16", "k-vpc-clash", "k-sg-clash")
	opened, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group, 22, "10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if !rulePort(opened.Items[0].Rules, 22) || !rulePort(opened.Items[0].Rules, 9) {
		t.Fatalf("stale retry stored %+v", opened.Items[0].Rules)
	}
}

func TestAuthorizeReplayStopsBeforeTheLabelCap(t *testing.T) {
	set, loop := startLoopWorld(t)
	ctx := t.Context()
	account, scope := replayAccount(t)
	group := replayGroup(t, ctx, set, scope, "10.8.0.0/16", "k-vpc-cap", "k-sg-cap")
	labels := make(map[string]string, 64)
	for i := 0; i < 64; i++ {
		labels[fmt.Sprintf("k%02d", i)] = "v"
	}
	loop.saveGroupLabels(group.String(), labels)
	changed, err := authorizeTCP(ctx, set, scope, "k-auth", "fp-auth", group, 22, "10.0.0.0/16")
	held, _ := loop.group(group.String(), account)
	if resource.CodeOf(err) != resource.CodeInvalidArgument || len(changed.Items) != 0 || len(held.Rules) != 0 {
		t.Fatalf("cap: %v items %+v rules %+v", err, changed.Items, held.Rules)
	}
}

func TestReplayRequestComparesFingerprint(t *testing.T) {
	account, _ := replayAccount(t)
	vpc, err := resource.Parse[resource.VpcID]("vpc-01234567")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.SecurityGroupID]("sg-01234567")
	if err != nil {
		t.Fatal(err)
	}
	w := newLoopWorld(backend.Set{}, time.Unix(1_700_000_000, 0).UTC())
	w.saveGroup(resource.SecurityGroup{ID: id, OwnerID: account, Name: "web", VpcID: vpc})
	srv := &groupSrv{w: w}
	name := securityGroupName(project(account), vpc.String(), id.String())
	ctx := t.Context()
	const requestID = "11111111-1111-4111-8111-111111111111"
	first, err := srv.UpdateSecurityGroup(ctx, groupUpdate(name, requestID, "aaaaaaaaaaaaaaaa", 22))
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.UpdateSecurityGroup(ctx, groupUpdate(name, requestID, "bbbbbbbbbbbbbbbb", 80))
	if status.Code(err) != codes.Aborted {
		t.Fatalf("different fingerprint: %v", err)
	}
	same, err := srv.UpdateSecurityGroup(ctx, groupUpdate(name, requestID, "aaaaaaaaaaaaaaaa", 80))
	if err != nil || same.GetName() != first.GetName() {
		t.Fatalf("same fingerprint: %v %s", err, same.GetName())
	}
	held, ok := w.group(id.String(), account)
	if !ok || len(held.Rules) != 1 || held.Rules[0].FromPort != 22 {
		t.Fatalf("replay applied a new body %+v", held.Rules)
	}
}

func TestUpdateSecurityGroupRejectsAStaleEtag(t *testing.T) {
	account, _ := replayAccount(t)
	vpc, err := resource.Parse[resource.VpcID]("vpc-01234567")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.SecurityGroupID]("sg-89abcdef")
	if err != nil {
		t.Fatal(err)
	}
	w := newLoopWorld(backend.Set{}, time.Unix(1_700_000_000, 0).UTC())
	w.saveGroup(resource.SecurityGroup{ID: id, OwnerID: account, Name: "web", VpcID: vpc})
	srv := &groupSrv{w: w}
	name := securityGroupName(project(account), vpc.String(), id.String())
	ctx := t.Context()
	_, err = srv.UpdateSecurityGroup(ctx, groupUpdate(
		name, "22222222-2222-4222-8222-222222222222", "aaaaaaaaaaaaaaaa", 22,
	))
	if err != nil {
		t.Fatal(err)
	}
	stale := groupUpdate(name, "33333333-3333-4333-8333-333333333333", "bbbbbbbbbbbbbbbb", 80)
	stale.SecurityGroup.Etag = "stale"
	if _, err := srv.UpdateSecurityGroup(ctx, stale); status.Code(err) != codes.Aborted {
		t.Fatalf("stale etag: %v", err)
	}
	held, ok := w.group(id.String(), account)
	if !ok || len(held.Rules) != 1 || held.Rules[0].FromPort != 22 {
		t.Fatalf("stale etag wrote %+v", held.Rules)
	}
}

func replayAccount(t *testing.T) (resource.AccountID, backend.Scope) {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return account, backend.Scope{Account: account}
}

func replayGroup(
	t *testing.T, ctx context.Context, set backend.Set, scope backend.Scope, cidr, vpcKey, groupKey string,
) resource.SecurityGroupID {
	t.Helper()
	vpc, err := set.Network.CreateVpc(ctx, backend.Mutation{
		Scope: scope, Key: vpcKey, Fingerprint: vpcKey,
	}, resource.CreateVpcRequest{Cidr: cidr})
	if err != nil {
		t.Fatal(err)
	}
	group, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: scope, Key: groupKey, Fingerprint: groupKey,
	}, resource.CreateSecurityGroupRequest{Name: "web", VpcID: vpc.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	return group.Items[0].ID
}

func groupUpdate(name, requestID, token string, port int32) *networkv1.UpdateSecurityGroupRequest {
	return &networkv1.UpdateSecurityGroupRequest{
		RequestId:  requestID,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.rules", "labels"}},
		SecurityGroup: &networkv1.SecurityGroup{
			Name: name,
			Labels: map[string]string{
				"vws-in-aaaaaaaaaaaaaaaa": token + " sg-01234567",
			},
			Spec: &networkv1.SecurityGroupSpec{Rules: []*networkv1.SecurityGroupRule{{
				Protocol: networkv1.Protocol_PROTOCOL_TCP,
				FromPort: port,
				ToPort:   port,
				Target:   &networkv1.SecurityGroupRule_Cidr{Cidr: "10.0.0.0/16"},
			}}},
		},
	}
}

func rulePort(rules []resource.IngressRule, port int) bool {
	for _, rule := range rules {
		if rule.FromPort == port {
			return true
		}
	}
	return false
}

func authorizeTCP(
	ctx context.Context, set backend.Set, scope backend.Scope,
	key, fp string, id resource.SecurityGroupID, port int, cidr string,
) (resource.Accepted[resource.SecurityGroup], error) {
	return set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{
		Scope: scope, Key: key, Fingerprint: fp,
	}, resource.AuthorizeSecurityGroupIngressRequest{
		ID: id,
		Rules: []resource.IngressChange{{
			IngressRule: resource.IngressRule{Protocol: "tcp", FromPort: port, ToPort: port, Cidr: cidr},
		}},
	})
}
