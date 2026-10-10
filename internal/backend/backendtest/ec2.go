package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func exerciseEC2(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, stopped resource.InstanceID) {
	t.Helper()
	scope := backend.Scope{Account: account}
	blank, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil || len(blank.Items) != 0 {
		t.Fatalf("boot volume leaked: %v %+v", err, blank.Items)
	}
	vpcReq := resource.CreateVpcRequest{Cidr: "10.8.0.0/16"}
	vm := backend.Mutation{Scope: scope, Key: "k-vpc", Fingerprint: "fp-vpc"}
	created, err := set.Network.CreateVpc(ctx, vm, vpcReq)
	if err != nil {
		t.Fatal(err)
	}
	if created.Items[0].State != resource.VpcPending || created.Items[0].OwnerID != account {
		t.Fatalf("vpc %+v", created.Items[0])
	}
	replay, err := set.Network.CreateVpc(ctx, vm, vpcReq)
	if err != nil || replay.Items[0].ID != created.Items[0].ID {
		t.Fatal("vpc retry")
	}
	clash := vm
	clash.Fingerprint = "other"
	if _, err := set.Network.CreateVpc(ctx, clash, vpcReq); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("vpc mismatch: %v", err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, created.Operation.ID); err != nil {
		t.Fatal(err)
	}
	vpcs, err := set.Network.DescribeVpcs(ctx, scope, resource.VpcQuery{
		IDs: []resource.VpcID{created.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(vpcs.Items) != 1 || vpcs.Items[0].State != resource.VpcAvailable {
		t.Fatalf("describe vpc: %v %+v", err, vpcs.Items)
	}
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "k-sub-vpc", Fingerprint: "fp-sub-vpc"}, resource.CreateSubnetRequest{
		Cidr: "10.8.1.0/24", VpcID: created.Items[0].ID,
	})
	if err != nil || sub.Items[0].VpcID != created.Items[0].ID {
		t.Fatalf("subnet in vpc: %v %+v", err, sub.Items)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.DeleteVpc(ctx, backend.Mutation{Scope: scope, Key: "k-del-vpc", Fingerprint: "fp-del-vpc"}, resource.DeleteVpcRequest{
		ID: created.Items[0].ID,
	}); resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("delete vpc: %v", err)
	}

	volReq := resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName}
	volM := backend.Mutation{Scope: scope, Key: "k-vol", Fingerprint: "fp-vol"}
	vol, err := set.Compute.CreateVolume(ctx, volM, volReq)
	if err != nil || vol.Items[0].State != resource.VolumeCreating {
		t.Fatalf("volume %+v %v", vol.Items, err)
	}
	if again, err := set.Compute.CreateVolume(ctx, volM, volReq); err != nil || again.Items[0].ID != vol.Items[0].ID {
		t.Fatal("volume retry")
	}
	if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{vol.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || listed.Items[0].State != resource.VolumeAvailable {
		t.Fatalf("describe volume: %v %+v", err, listed.Items)
	}
	attached, err := set.Compute.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-attach", Fingerprint: "fp-attach"}, resource.AttachVolumeRequest{
		VolumeID: vol.Items[0].ID, InstanceID: stopped, Device: "/dev/sdf",
	})
	if err != nil || attached.Items[0].State != resource.VolumeInUse || attached.Items[0].InstanceID != stopped {
		t.Fatalf("attach: %v %+v", err, attached.Items)
	}
	if _, err := set.Compute.DeleteVolume(ctx, backend.Mutation{Scope: scope, Key: "k-del-busy", Fingerprint: "fp-del-busy"}, resource.DeleteVolumeRequest{
		ID: vol.Items[0].ID,
	}); resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("delete busy volume: %v", err)
	}
	extra, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "k-vol-2", Fingerprint: "fp-vol-2"}, volReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, extra.Operation.ID); err != nil {
		t.Fatal(err)
	}
	deleted, err := set.Compute.DeleteVolume(ctx, backend.Mutation{Scope: scope, Key: "k-del-vol", Fingerprint: "fp-del-vol"}, resource.DeleteVolumeRequest{ID: extra.Items[0].ID})
	if err != nil || deleted.Items[0].State != resource.VolumeDeleting {
		t.Fatalf("delete volume: %v %+v", err, deleted.Items)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, deleted.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{extra.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("deleted volume: %v", err)
	}

	missing, err := resource.Parse[resource.InstanceID]("i-01234567")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.StartInstances(ctx, backend.Mutation{Scope: scope, Key: "k-start-partial", Fingerprint: "fp-start-partial"}, resource.StartInstancesRequest{
		IDs: []resource.InstanceID{stopped, missing},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("partial start: %v", err)
	}
	still, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{stopped}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || still.Items[0].State != resource.InstanceStopped {
		t.Fatalf("partial start applied: %v %+v", err, still.Items)
	}
	started, err := set.Compute.StartInstances(ctx, backend.Mutation{Scope: scope, Key: "k-start", Fingerprint: "fp-start"}, resource.StartInstancesRequest{
		IDs: []resource.InstanceID{stopped},
	})
	if err != nil || started.Items[0].Current != resource.InstancePending || started.Items[0].Previous != resource.InstanceStopped {
		t.Fatalf("start: %v %+v", err, started.Items)
	}
	startedOp, err := set.Compute.GetOperation(ctx, scope, started.Operation.ID)
	if err != nil || startedOp.Action != resource.ActionStartInstances {
		t.Fatalf("start operation: %v %s", err, startedOp.Action)
	}
	running, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{stopped}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || running.Items[0].State != resource.InstanceRunning {
		t.Fatalf("started: %v %+v", err, running.Items)
	}
	terminated, err := set.Compute.TerminateInstances(ctx, backend.Mutation{Scope: scope, Key: "k-term", Fingerprint: "fp-term"}, resource.TerminateInstancesRequest{
		IDs: []resource.InstanceID{stopped},
	})
	if err != nil || terminated.Items[0].Current != resource.InstanceShuttingDown {
		t.Fatalf("terminate: %v %+v", err, terminated.Items)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, terminated.Operation.ID); err != nil {
		t.Fatal(err)
	}
	done, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{stopped}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || done.Items[0].State != resource.InstanceTerminated {
		t.Fatalf("terminated: %v %+v", err, done.Items)
	}

	group, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-sg", Fingerprint: "fp-sg"}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: created.Items[0].ID,
	})
	if err != nil || group.Items[0].Name != "web" || group.Items[0].VpcID != created.Items[0].ID {
		t.Fatalf("group: %v %+v", err, group.Items)
	}
	if _, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-sg-2", Fingerprint: "fp-sg-2"}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: created.Items[0].ID,
	}); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("duplicate group: %v", err)
	}
	opened, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{Scope: scope, Key: "k-auth", Fingerprint: "fp-auth"}, resource.AuthorizeSecurityGroupIngressRequest{
		ID: group.Items[0].ID, Rule: resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
	})
	if err != nil || len(opened.Items[0].Rules) != 1 || opened.Items[0].Rules[0].Protocol != "tcp" {
		t.Fatalf("authorize: %v %+v", err, opened.Items)
	}
	if _, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{Scope: scope, Key: "k-auth-2", Fingerprint: "fp-auth-2"}, resource.AuthorizeSecurityGroupIngressRequest{
		ID: group.Items[0].ID, Rule: resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
	}); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("duplicate rule: %v", err)
	}
	openedMore, err := set.Network.AuthorizeSecurityGroupIngress(ctx, backend.Mutation{Scope: scope, Key: "k-auth-3", Fingerprint: "fp-auth-3"}, resource.AuthorizeSecurityGroupIngressRequest{
		ID: group.Items[0].ID, Rule: resource.IngressRule{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"},
	})
	if err != nil || len(openedMore.Items[0].Rules) != 2 {
		t.Fatalf("second rule: %v %+v", err, openedMore.Items)
	}

	keyM := backend.Mutation{Scope: scope, Key: "k-key", Fingerprint: "fp-key"}
	key, err := set.Compute.CreateKeyPair(ctx, keyM, resource.CreateKeyPairRequest{Name: "admin"})
	if err != nil || key.Items[0].Name != "admin" || key.Items[0].Material == "" || key.Items[0].Fingerprint == "" {
		t.Fatalf("key: %v %+v", err, key.Items)
	}
	againKey, err := set.Compute.CreateKeyPair(ctx, keyM, resource.CreateKeyPairRequest{Name: "admin"})
	if err != nil || againKey.Items[0].Material != key.Items[0].Material || againKey.Items[0].ID != key.Items[0].ID {
		t.Fatal("key retry")
	}
	if _, err := set.Compute.CreateKeyPair(ctx, backend.Mutation{Scope: scope, Key: "k-key-2", Fingerprint: "fp-key-2"}, resource.CreateKeyPairRequest{Name: "admin"}); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("duplicate key: %v", err)
	}

	images, err := set.Compute.DescribeImages(ctx, scope, resource.ImageQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil || len(images.Items) != 1 || images.Items[0].ID.String() != "ami-0123456789abcdef0" || images.Items[0].OwnerID != account {
		t.Fatalf("images: %v %+v", err, images.Items)
	}
	unknown, err := resource.Parse[resource.ImageID]("ami-01234567")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.DescribeImages(ctx, scope, resource.ImageQuery{
		IDs: []resource.ImageID{unknown}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("unknown image: %v", err)
	}
}
