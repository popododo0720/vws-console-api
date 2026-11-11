package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func requireCapabilities(
	t *testing.T, caps resource.RegionCapabilities, actions []resource.Action, reads []resource.ReadAction,
) {
	t.Helper()
	check := func(key string, cap resource.ActionCapability) {
		t.Helper()
		if cap.State != resource.ActionSupported && cap.State != resource.ActionPartial {
			reason := cap.Reason
			if reason == "" {
				reason = "region declares an empty read"
			}
			t.Skipf("%s: %s (%s)", key, reason, cap.State)
		}
	}
	for _, action := range actions {
		check(action.CapabilityKey(), caps.Mutation(action))
	}
	for _, read := range reads {
		check(read.CapabilityKey(), caps.Read(read))
	}
}

type capabilityReporter interface {
	Helper()
	Errorf(string, ...any)
}

func capabilityContract(t capabilityReporter, set backend.Set, caps resource.RegionCapabilities) {
	t.Helper()
	ctx := context.Background()
	account := probeID[resource.AccountID]("123456789012")
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "capability", Fingerprint: "capability"}
	mutations := mutationProbes(ctx, set, m)
	for _, action := range resource.Actions() {
		calls, ok := mutations[action]
		if !ok || len(calls) == 0 {
			t.Errorf("%s: missing mutation probe", action.CapabilityKey())
			continue
		}
		if caps.Mutation(action).State != resource.ActionUnsupported {
			continue
		}
		for i, call := range calls {
			if err := call(); resource.CodeOf(err) != resource.CodeOf(resource.Unsupported("", "")) ||
				!resource.IsUnsupported(resource.AsError(err)) {
				t.Errorf("%s method %d: want UnsupportedOperation, got %v", action.CapabilityKey(), i, err)
			}
		}
	}
	reads := readProbes(ctx, set, m.Scope)
	for _, action := range resource.ReadActions() {
		call, ok := reads[action]
		if !ok {
			t.Errorf("%s: missing read probe", action.CapabilityKey())
			continue
		}
		if caps.Read(action).State != resource.ActionEmpty {
			continue
		}
		count, token, err := call()
		if err != nil || count != 0 || token != "" {
			t.Errorf("%s: want empty successful page, got items=%d token=%q error=%v",
				action.CapabilityKey(), count, token, err)
		}
	}
}

func mutationProbe[Q, R any](ctx context.Context, m backend.Mutation,
	call func(context.Context, backend.Mutation, Q) (R, error), req Q,
) func() error {
	return func() error { _, err := call(ctx, m, req); return err }
}

func mutationProbes(ctx context.Context, set backend.Set, m backend.Mutation) map[resource.Action][]func() error {
	instance := probeID[resource.InstanceID]("i-0123456789abcdef0")
	image := probeID[resource.ImageID]("ami-0123456789abcdef0")
	volume := probeID[resource.VolumeID]("vol-0123456789abcdef0")
	subnet := probeID[resource.SubnetID]("subnet-0123456789abcdef0")
	vpc := probeID[resource.VpcID]("vpc-0123456789abcdef0")
	snapshot := probeID[resource.SnapshotID]("snap-0123456789abcdef0")
	group := probeID[resource.SecurityGroupID]("sg-0123456789abcdef0")
	address := probeID[resource.AddressID]("eipalloc-0123456789abcdef0")
	tags := map[string]string{"Name": "capability"}
	rule := resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.2.0.0/24"}
	return map[resource.Action][]func() error{
		resource.ActionRunInstances: {mutationProbe(ctx, m, set.Compute.RunInstances,
			resource.RunInstancesRequest{ImageID: image, SubnetID: subnet, InstanceType: "vws.small", Count: 1})},
		resource.ActionStopInstances: {mutationProbe(ctx, m, set.Compute.StopInstances,
			resource.StopInstancesRequest{IDs: []resource.InstanceID{instance}})},
		resource.ActionStartInstances: {mutationProbe(ctx, m, set.Compute.StartInstances,
			resource.StartInstancesRequest{IDs: []resource.InstanceID{instance}})},
		resource.ActionRebootInstances: {mutationProbe(ctx, m, set.Compute.RebootInstances,
			resource.RebootInstancesRequest{IDs: []resource.InstanceID{instance}})},
		resource.ActionTerminateInstances: {
			mutationProbe(ctx, m, set.Compute.TerminateInstances,
				resource.TerminateInstancesRequest{IDs: []resource.InstanceID{instance}}),
		},
		resource.ActionCreateSubnet: {mutationProbe(ctx, m, set.Network.CreateSubnet,
			resource.CreateSubnetRequest{Cidr: "10.2.0.0/24"})},
		resource.ActionDeleteSubnet: {mutationProbe(ctx, m, set.Network.DeleteSubnet,
			resource.DeleteSubnetRequest{ID: subnet})},
		resource.ActionCreateVpc: {mutationProbe(ctx, m, set.Network.CreateVpc,
			resource.CreateVpcRequest{Cidr: "10.2.0.0/16"})},
		resource.ActionDeleteVpc: {mutationProbe(ctx, m, set.Network.DeleteVpc, resource.DeleteVpcRequest{ID: vpc})},
		resource.ActionCreateVolume: {mutationProbe(ctx, m, set.Compute.CreateVolume,
			resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2})},
		resource.ActionAttachVolume: {mutationProbe(ctx, m, set.Compute.AttachVolume,
			resource.AttachVolumeRequest{VolumeID: volume, InstanceID: instance, Device: "/dev/sdf"})},
		resource.ActionDetachVolume: {mutationProbe(ctx, m, set.Compute.DetachVolume,
			resource.DetachVolumeRequest{VolumeID: volume, InstanceID: instance, Device: "/dev/sdf"})},
		resource.ActionDeleteVolume: {mutationProbe(ctx, m, set.Compute.DeleteVolume,
			resource.DeleteVolumeRequest{ID: volume})},
		resource.ActionModifyVolume: {mutationProbe(ctx, m, set.Compute.ModifyVolume,
			resource.ModifyVolumeRequest{ID: volume, SizeGiB: 16})},
		resource.ActionCreateKeyPair: {mutationProbe(ctx, m, set.Compute.CreateKeyPair,
			resource.CreateKeyPairRequest{Name: "capability", Type: resource.KeyTypeEd25519})},
		resource.ActionDeleteKeyPair: {mutationProbe(ctx, m, set.Compute.DeleteKeyPair,
			resource.DeleteKeyPairRequest{Name: "capability"})},
		resource.ActionCreateSnapshot: {mutationProbe(ctx, m, set.Compute.CreateSnapshot,
			resource.CreateSnapshotRequest{VolumeID: volume})},
		resource.ActionDeleteSnapshot: {mutationProbe(ctx, m, set.Compute.DeleteSnapshot,
			resource.DeleteSnapshotRequest{ID: snapshot})},
		resource.ActionRegisterImage: {mutationProbe(ctx, m, set.Compute.RegisterImage,
			resource.RegisterImageRequest{Name: "capability", SnapshotID: snapshot})},
		resource.ActionCreateSecurityGroup: {mutationProbe(ctx, m, set.Network.CreateSecurityGroup,
			resource.CreateSecurityGroupRequest{VpcID: vpc, Name: "capability"})},
		resource.ActionDeleteSecurityGroup: {
			mutationProbe(ctx, m, set.Network.DeleteSecurityGroup, resource.DeleteSecurityGroupRequest{ID: group}),
		},
		resource.ActionAuthorizeSecurityGroupIngress: {
			mutationProbe(ctx, m, set.Network.AuthorizeSecurityGroupIngress,
				resource.AuthorizeSecurityGroupIngressRequest{ID: group, Rules: []resource.IngressRule{rule}}),
		},
		resource.ActionRevokeSecurityGroupIngress: {
			mutationProbe(ctx, m, set.Network.RevokeSecurityGroupIngress,
				resource.RevokeSecurityGroupIngressRequest{ID: group, Rule: rule}),
		},
		resource.ActionAllocateAddress: {mutationProbe(ctx, m, set.Network.AllocateAddress,
			resource.AllocateAddressRequest{Domain: "vpc"})},
		resource.ActionReleaseAddress: {mutationProbe(ctx, m, set.Network.ReleaseAddress,
			resource.ReleaseAddressRequest{ID: address})},
		resource.ActionAssociateAddress: {
			mutationProbe(ctx, m, set.Network.AssociateAddress,
				resource.AssociateAddressRequest{ID: address, InstanceID: instance}),
		},
		resource.ActionDisassociateAddress: {
			mutationProbe(ctx, m, set.Network.DisassociateAddress, resource.DisassociateAddressRequest{ID: address}),
		},
		resource.ActionCreateTags: {
			mutationProbe(ctx, m, set.Compute.TagVolumes,
				resource.TagVolumesRequest{IDs: []resource.VolumeID{volume}, Tags: tags}),
			mutationProbe(ctx, m, set.Compute.CreateTags,
				resource.CreateTagsRequest{IDs: []resource.InstanceID{instance}, Tags: tags}),
			mutationProbe(ctx, m, set.Network.TagVpcs, resource.TagVpcsRequest{IDs: []resource.VpcID{vpc}, Tags: tags}),
			mutationProbe(ctx, m, set.Network.TagSubnets,
				resource.TagSubnetsRequest{IDs: []resource.SubnetID{subnet}, Tags: tags}),
		},
		resource.ActionDeleteTags: {
			mutationProbe(ctx, m, set.Compute.UntagVolumes, resource.UntagVolumesRequest{IDs: []resource.VolumeID{volume}}),
			mutationProbe(ctx, m, set.Compute.DeleteTags, resource.DeleteTagsRequest{IDs: []resource.InstanceID{instance}}),
			mutationProbe(ctx, m, set.Network.UntagVpcs, resource.UntagVpcsRequest{IDs: []resource.VpcID{vpc}}),
			mutationProbe(ctx, m, set.Network.UntagSubnets, resource.UntagSubnetsRequest{IDs: []resource.SubnetID{subnet}}),
		},
	}
}

func readProbe[Q, R any](ctx context.Context, scope backend.Scope,
	call func(context.Context, backend.Scope, Q) (resource.Page[R], error), query Q,
) func() (int, string, error) {
	return func() (int, string, error) {
		page, err := call(ctx, scope, query)
		return len(page.Items), page.NextToken, err
	}
}

func readProbes(
	ctx context.Context, set backend.Set, scope backend.Scope,
) map[resource.ReadAction]func() (int, string, error) {
	page := resource.PageRequest{Size: 50}
	return map[resource.ReadAction]func() (int, string, error){
		resource.ReadDescribeInstances: readProbe(ctx, scope, set.Compute.DescribeInstances,
			resource.InstanceQuery{Page: page}),
		resource.ReadDescribeImages:  readProbe(ctx, scope, set.Compute.DescribeImages, resource.ImageQuery{Page: page}),
		resource.ReadDescribeVolumes: readProbe(ctx, scope, set.Compute.DescribeVolumes, resource.VolumeQuery{Page: page}),
		resource.ReadDescribeSnapshots: readProbe(ctx, scope, set.Compute.DescribeSnapshots,
			resource.SnapshotQuery{Page: page}),
		resource.ReadDescribeKeyPairs: readProbe(ctx, scope, set.Compute.DescribeKeyPairs, resource.KeyPairQuery{Page: page}),
		resource.ReadDescribeVpcs:     readProbe(ctx, scope, set.Network.DescribeVpcs, resource.VpcQuery{Page: page}),
		resource.ReadDescribeSubnets:  readProbe(ctx, scope, set.Network.DescribeSubnets, resource.SubnetQuery{Page: page}),
		resource.ReadDescribeSecurityGroups: readProbe(ctx, scope, set.Network.DescribeSecurityGroups,
			resource.SecurityGroupQuery{Page: page}),
		resource.ReadDescribeAddresses: readProbe(ctx, scope, set.Network.DescribeAddresses,
			resource.AddressQuery{Page: page}),
	}
}

func probeID[T any, P interface {
	*T
	UnmarshalText([]byte) error
}](value string) T {
	id, err := resource.Parse[T, P](value)
	if err != nil {
		panic(err)
	}
	return id
}
