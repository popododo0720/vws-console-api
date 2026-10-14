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
	grown, err := set.Compute.ModifyVolume(ctx, backend.Mutation{Scope: scope, Key: "k-grow", Fingerprint: "fp-grow"}, resource.ModifyVolumeRequest{
		ID: extra.Items[0].ID, SizeGiB: 12,
	})
	if err != nil || grown.Items[0].SizeGiB != 12 || grown.Operation.Action != resource.ActionModifyVolume {
		t.Fatalf("modify volume: %v %+v", err, grown)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, grown.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{extra.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); err != nil || got.Items[0].SizeGiB != 12 {
		t.Fatalf("size after modify: %v %+v", err, got.Items)
	}
	if _, err := set.Compute.ModifyVolume(ctx, backend.Mutation{Scope: scope, Key: "k-shrink", Fingerprint: "fp-shrink"}, resource.ModifyVolumeRequest{
		ID: extra.Items[0].ID, SizeGiB: 4,
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("shrink: %v", err)
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
	if _, err := set.Network.DeleteSubnet(ctx, backend.Mutation{Scope: scope, Key: "k-del-sub-busy", Fingerprint: "fp-del-sub-busy"}, resource.DeleteSubnetRequest{
		ID: running.Items[0].SubnetID,
	}); resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("delete busy subnet: %v", err)
	}
	eip, err := set.Network.AllocateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-addr-assoc", Fingerprint: "fp-addr-assoc"}, resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil {
		t.Fatal(err)
	}
	assoc, err := set.Network.AssociateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-assoc", Fingerprint: "fp-assoc"}, resource.AssociateAddressRequest{
		ID: eip.Items[0].ID, InstanceID: stopped,
	})
	if err != nil || assoc.Items[0].InstanceID != stopped || assoc.Operation.Action != resource.ActionAssociateAddress {
		t.Fatalf("associate: %v %+v", err, assoc)
	}
	associated, err := set.Network.DescribeAddresses(ctx, scope, resource.AddressQuery{
		IDs: []resource.AddressID{eip.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || associated.Items[0].InstanceID != stopped {
		t.Fatalf("describe associated: %v %+v", err, associated.Items)
	}
	dis, err := set.Network.DisassociateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-disassoc", Fingerprint: "fp-disassoc"}, resource.DisassociateAddressRequest{
		ID: eip.Items[0].ID,
	})
	if err != nil || !dis.Items[0].InstanceID.IsZero() || dis.Operation.Action != resource.ActionDisassociateAddress {
		t.Fatalf("disassociate: %v %+v", err, dis)
	}
	idle, err := set.Network.DescribeAddresses(ctx, scope, resource.AddressQuery{
		IDs: []resource.AddressID{eip.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || !idle.Items[0].InstanceID.IsZero() {
		t.Fatalf("describe disassociated: %v %+v", err, idle.Items)
	}
	unknownAddr, err := resource.Parse[resource.AddressID]("eipalloc-00000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]resource.AddressID{"idle": eip.Items[0].ID, "unknown": unknownAddr} {
		_, err := set.Network.DisassociateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-disassoc-" + name, Fingerprint: "fp-disassoc-" + name}, resource.DisassociateAddressRequest{ID: id})
		if e := resource.AsError(err); e == nil || e.Code != resource.CodeNotFound || e.Kind != resource.KindAddress || e.Field != "associationId" {
			t.Fatalf("disassociate %s address: %v", name, err)
		}
	}
	if _, err := set.Network.ReleaseAddress(ctx, backend.Mutation{Scope: scope, Key: "k-rel-assoc", Fingerprint: "fp-rel-assoc"}, resource.ReleaseAddressRequest{ID: eip.Items[0].ID}); err != nil {
		t.Fatal(err)
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

	keys, err := set.Compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{
		Names: []string{"admin"}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(keys.Items) != 1 || keys.Items[0].ID != key.Items[0].ID || keys.Items[0].Material != "" || keys.Items[0].Fingerprint != key.Items[0].Fingerprint {
		t.Fatalf("describe keys: %v %+v", err, keys.Items)
	}
	keyDel := backend.Mutation{Scope: scope, Key: "k-del-key", Fingerprint: "fp-del-key"}
	deletedKey, err := set.Compute.DeleteKeyPair(ctx, keyDel, resource.DeleteKeyPairRequest{Name: "admin"})
	if err != nil || deletedKey.Items[0].ID != key.Items[0].ID || deletedKey.Items[0].Material != "" {
		t.Fatalf("delete key: %v %+v", err, deletedKey.Items)
	}
	deletedKeyOp, err := set.Compute.GetOperation(ctx, scope, deletedKey.Operation.ID)
	if err != nil || deletedKeyOp.Action != resource.ActionDeleteKeyPair {
		t.Fatalf("delete key operation: %v %s", err, deletedKeyOp.Action)
	}
	retriedKey, err := set.Compute.DeleteKeyPair(ctx, keyDel, resource.DeleteKeyPairRequest{ID: key.Items[0].ID})
	if err != nil || retriedKey.Items[0].ID != key.Items[0].ID || retriedKey.Operation.ID != deletedKey.Operation.ID {
		t.Fatalf("delete key retry: %v %+v", err, retriedKey.Items)
	}
	if _, err := set.Compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{
		IDs: []resource.KeyPairID{key.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("deleted key: %v", err)
	}

	otherVpc, err := set.Network.CreateVpc(ctx, backend.Mutation{Scope: scope, Key: "k-vpc-2", Fingerprint: "fp-vpc-2"}, resource.CreateVpcRequest{Cidr: "10.9.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, otherVpc.Operation.ID); err != nil {
		t.Fatal(err)
	}
	otherGroup, err := set.Network.CreateSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-sg-other", Fingerprint: "fp-sg-other"}, resource.CreateSecurityGroupRequest{
		Name: "web", VpcID: otherVpc.Items[0].ID,
	})
	if err != nil || otherGroup.Items[0].VpcID != otherVpc.Items[0].ID {
		t.Fatalf("second group: %v %+v", err, otherGroup.Items)
	}
	if _, err := set.Network.DeleteSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-del-sg-name", Fingerprint: "fp-del-sg-name"}, resource.DeleteSecurityGroupRequest{Name: "web"}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("ambiguous group name: %v", err)
	}
	deletedOther, err := set.Network.DeleteSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-del-sg-other", Fingerprint: "fp-del-sg-other"}, resource.DeleteSecurityGroupRequest{ID: otherGroup.Items[0].ID})
	if err != nil || deletedOther.Items[0].ID != otherGroup.Items[0].ID {
		t.Fatalf("delete other group: %v %+v", err, deletedOther.Items)
	}
	if _, err := set.Network.GetOperation(ctx, scope, deletedOther.Operation.ID); err != nil {
		t.Fatal(err)
	}

	groups, err := set.Network.DescribeSecurityGroups(ctx, scope, resource.SecurityGroupQuery{
		Names: []string{"web"}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(groups.Items) != 1 || groups.Items[0].ID != group.Items[0].ID || len(groups.Items[0].Rules) != 2 {
		t.Fatalf("describe groups: %v %+v", err, groups.Items)
	}
	deletedGroup, err := set.Network.DeleteSecurityGroup(ctx, backend.Mutation{Scope: scope, Key: "k-del-sg", Fingerprint: "fp-del-sg"}, resource.DeleteSecurityGroupRequest{ID: group.Items[0].ID})
	if err != nil || deletedGroup.Items[0].ID != group.Items[0].ID {
		t.Fatalf("delete group: %v %+v", err, deletedGroup.Items)
	}
	deletedGroupOp, err := set.Network.GetOperation(ctx, scope, deletedGroup.Operation.ID)
	if err != nil || deletedGroupOp.Action != resource.ActionDeleteSecurityGroup {
		t.Fatalf("delete group operation: %v %s", err, deletedGroupOp.Action)
	}
	if _, err := set.Network.DescribeSecurityGroups(ctx, scope, resource.SecurityGroupQuery{
		IDs: []resource.SecurityGroupID{group.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("deleted group: %v", err)
	}

	deletedSub, err := set.Network.DeleteSubnet(ctx, backend.Mutation{Scope: scope, Key: "k-del-sub", Fingerprint: "fp-del-sub"}, resource.DeleteSubnetRequest{ID: sub.Items[0].ID})
	if err != nil || deletedSub.Items[0].ID != sub.Items[0].ID {
		t.Fatalf("delete subnet: %v %+v", err, deletedSub.Items)
	}
	deletedSubOp, err := set.Network.GetOperation(ctx, scope, deletedSub.Operation.ID)
	if err != nil || deletedSubOp.Action != resource.ActionDeleteSubnet {
		t.Fatalf("delete subnet operation: %v %s", err, deletedSubOp.Action)
	}
	if _, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{
		IDs: []resource.SubnetID{sub.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("deleted subnet: %v", err)
	}
	recreated, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "k-sub-vpc", Fingerprint: "fp-sub-vpc"}, resource.CreateSubnetRequest{
		Cidr: "10.8.1.0/24", VpcID: created.Items[0].ID,
	})
	if err != nil || recreated.Items[0].ID == sub.Items[0].ID {
		t.Fatalf("recreate subnet: %v %+v", err, recreated.Items)
	}

	addr, err := set.Network.AllocateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-addr", Fingerprint: "fp-addr"}, resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil || addr.Items[0].PublicIP == "" || addr.Items[0].Domain != "vpc" {
		t.Fatalf("address: %v %+v", err, addr.Items)
	}
	addrOp, err := set.Network.GetOperation(ctx, scope, addr.Operation.ID)
	if err != nil || addrOp.Action != resource.ActionAllocateAddress {
		t.Fatalf("allocate operation: %v %s", err, addrOp.Action)
	}
	addrs, err := set.Network.DescribeAddresses(ctx, scope, resource.AddressQuery{
		PublicIPs: []string{addr.Items[0].PublicIP}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(addrs.Items) != 1 || addrs.Items[0].ID != addr.Items[0].ID {
		t.Fatalf("describe addresses: %v %+v", err, addrs.Items)
	}
	if _, err := set.Network.AssociateAddress(ctx, backend.Mutation{Scope: scope, Key: "k-assoc-gone", Fingerprint: "fp-assoc-gone"}, resource.AssociateAddressRequest{
		ID: addr.Items[0].ID, InstanceID: stopped,
	}); resource.AsError(err) == nil || resource.AsError(err).Kind != resource.KindInstance || resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("associate terminated instance: %v", err)
	}
	rel := backend.Mutation{Scope: scope, Key: "k-rel-addr", Fingerprint: "fp-rel-addr"}
	released, err := set.Network.ReleaseAddress(ctx, rel, resource.ReleaseAddressRequest{ID: addr.Items[0].ID})
	if err != nil || released.Items[0].ID != addr.Items[0].ID {
		t.Fatalf("release: %v %+v", err, released.Items)
	}
	releasedOp, err := set.Network.GetOperation(ctx, scope, released.Operation.ID)
	if err != nil || releasedOp.Action != resource.ActionReleaseAddress {
		t.Fatalf("release operation: %v %s", err, releasedOp.Action)
	}
	retriedRel, err := set.Network.ReleaseAddress(ctx, rel, resource.ReleaseAddressRequest{ID: addr.Items[0].ID})
	if err != nil || retriedRel.Items[0].ID != addr.Items[0].ID || retriedRel.Operation.ID != released.Operation.ID {
		t.Fatalf("release retry: %v %+v", err, retriedRel.Items)
	}
	if _, err := set.Network.DescribeAddresses(ctx, scope, resource.AddressQuery{
		IDs: []resource.AddressID{addr.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("released address: %v", err)
	}

	snap, err := set.Compute.CreateSnapshot(ctx, backend.Mutation{Scope: scope, Key: "k-snap", Fingerprint: "fp-snap"}, resource.CreateSnapshotRequest{
		VolumeID: vol.Items[0].ID, Description: "daily",
	})
	if err != nil || snap.Items[0].VolumeID != vol.Items[0].ID || snap.Items[0].State != resource.SnapshotPending || snap.Items[0].VolumeSize != vol.Items[0].SizeGiB {
		t.Fatalf("snapshot: %v %+v", err, snap.Items)
	}
	snapOp, err := set.Compute.GetOperation(ctx, scope, snap.Operation.ID)
	if err != nil || snapOp.Action != resource.ActionCreateSnapshot {
		t.Fatalf("snapshot operation: %v %s", err, snapOp.Action)
	}
	snaps, err := set.Compute.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{
		IDs: []resource.SnapshotID{snap.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(snaps.Items) != 1 || snaps.Items[0].State != resource.SnapshotCompleted || snaps.Items[0].Description != "daily" {
		t.Fatalf("describe snapshots: %v %+v", err, snaps.Items)
	}
	restored, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "k-restore", Fingerprint: "fp-restore"}, resource.CreateVolumeRequest{
		Zone: resource.ZoneName, Type: resource.VolumeGP2, SnapshotID: snap.Items[0].ID,
	})
	if err != nil || restored.Items[0].SnapshotID != snap.Items[0].ID || restored.Items[0].SizeGiB != snap.Items[0].VolumeSize {
		t.Fatalf("restore volume: %v %+v", err, restored.Items)
	}
	restoredRows, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{restored.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(restoredRows.Items) != 1 || restoredRows.Items[0].SnapshotID != snap.Items[0].ID || restoredRows.Items[0].SizeGiB != snap.Items[0].VolumeSize {
		t.Fatalf("describe restored volume: %v %+v", err, restoredRows.Items)
	}
	if _, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "k-restore-small", Fingerprint: "fp-restore-small"}, resource.CreateVolumeRequest{
		SizeGiB: snap.Items[0].VolumeSize - 1, Zone: resource.ZoneName, Type: resource.VolumeGP2, SnapshotID: snap.Items[0].ID,
	}); snap.Items[0].VolumeSize > 1 && resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("restore smaller than the snapshot: %v", err)
	}
	if _, err := set.Compute.DeleteVolume(ctx, backend.Mutation{Scope: scope, Key: "k-del-restore", Fingerprint: "fp-del-restore"}, resource.DeleteVolumeRequest{
		ID: restored.Items[0].ID,
	}); err != nil {
		t.Fatalf("delete restored volume: %v", err)
	}
	snapDel := backend.Mutation{Scope: scope, Key: "k-del-snap", Fingerprint: "fp-del-snap"}
	deletedSnap, err := set.Compute.DeleteSnapshot(ctx, snapDel, resource.DeleteSnapshotRequest{ID: snap.Items[0].ID})
	if err != nil || deletedSnap.Items[0].ID != snap.Items[0].ID {
		t.Fatalf("delete snapshot: %v %+v", err, deletedSnap.Items)
	}
	deletedSnapOp, err := set.Compute.GetOperation(ctx, scope, deletedSnap.Operation.ID)
	if err != nil || deletedSnapOp.Action != resource.ActionDeleteSnapshot {
		t.Fatalf("delete snapshot operation: %v %s", err, deletedSnapOp.Action)
	}
	retriedSnap, err := set.Compute.DeleteSnapshot(ctx, snapDel, resource.DeleteSnapshotRequest{ID: snap.Items[0].ID})
	if err != nil || retriedSnap.Items[0].ID != snap.Items[0].ID || retriedSnap.Operation.ID != deletedSnap.Operation.ID {
		t.Fatalf("delete snapshot retry: %v %+v", err, retriedSnap.Items)
	}
	if _, err := set.Compute.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{
		IDs: []resource.SnapshotID{snap.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("deleted snapshot: %v", err)
	}
}
