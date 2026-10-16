package grpcclient

import (
	"context"
	"strings"
	"testing"

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
