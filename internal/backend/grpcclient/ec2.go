package grpcclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (c computeClient) StartInstances(ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, req.IDs, resource.ActionStartInstances, computev1.InstancePower_INSTANCE_POWER_RUNNING)
}

func (c computeClient) TerminateInstances(ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	projectID := project(m.Account)
	prev := make([]resource.Instance, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if _, _, err := resource.NextInstanceState(resource.ActionTerminateInstances, inst.State); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		prev = append(prev, inst)
	}
	var op resource.Operation
	items := make([]resource.InstanceStateChange, 0, len(prev))
	for i, inst := range prev {
		mid, _, err := resource.NextInstanceState(resource.ActionTerminateInstances, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		deleted, err := c.instances.DeleteInstance(ctx, &computev1.DeleteInstanceRequest{
			Name:      instanceName(projectID, inst.ID.String()),
			RequestId: requestUUID(m.Key, "terminate", hex.EncodeToString([]byte{byte(i)})),
		})
		if err := rpcErr(deleted, err); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if i == 0 {
			op, err = operationFrom(deleted, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.InstanceStateChange]{}, err
			}
		}
		items = append(items, resource.InstanceStateChange{
			ID: inst.ID, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
	}
	op.Action = resource.ActionTerminateInstances
	op.Targets = stateRefs(items)
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

func (c computeClient) changeInstances(ctx context.Context, m backend.Mutation, ids []resource.InstanceID, action resource.Action, power computev1.InstancePower) (resource.Accepted[resource.InstanceStateChange], error) {
	projectID := project(m.Account)
	prev := make([]resource.Instance, 0, len(ids))
	for _, id := range ids {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if _, _, err := resource.NextInstanceState(action, inst.State); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		prev = append(prev, inst)
	}
	var op resource.Operation
	items := make([]resource.InstanceStateChange, 0, len(prev))
	for i, inst := range prev {
		mid, _, err := resource.NextInstanceState(action, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		updated, err := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
			RequestId:  requestUUID(m.Key, action.String(), hex.EncodeToString([]byte{byte(i)})),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.power", "labels"}},
			Instance: &computev1.Instance{
				Name: instanceName(projectID, inst.ID.String()),
				Labels: withInternalLabels(inst.Tags, map[string]string{
					labelAction:      action.String(),
					labelFingerprint: clip(m.Fingerprint, 63),
					labelImage:       inst.ImageID.String(),
					labelReservation: inst.ReservationID.String(),
				}),
				Spec: &computev1.InstanceSpec{
					MachineType: inst.InstanceType,
					Power:       power,
					NetworkInterfaces: []*computev1.NetworkInterface{{
						DeviceName: "nic0",
						Subnet:     subnetName(projectID, "", inst.SubnetID.String()),
					}},
				},
			},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if i == 0 {
			op, err = operationFrom(updated, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.InstanceStateChange]{}, err
			}
		}
		items = append(items, resource.InstanceStateChange{
			ID: inst.ID, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
	}
	op.Action = action
	op.Targets = stateRefs(items)
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

func (c computeClient) CreateVolume(ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	spec := &storagev1.VolumeSpec{SizeGib: req.SizeGiB, Type: storageType(req.Type)}
	if !req.SnapshotID.IsZero() {
		// A size of 0 is the snapshot size, which only the snapshot knows.
		snap, err := c.getSnapshot(ctx, projectID, req.SnapshotID.String())
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		if req.SizeGiB == 0 {
			req.SizeGiB = snap.VolumeSize
			spec.SizeGib = snap.VolumeSize
		}
		if req.SizeGiB < snap.VolumeSize {
			return resource.Accepted[resource.Volume]{}, resource.Invalid("size", "smaller than the snapshot")
		}
		spec.Source = &storagev1.VolumeSpec_Snapshot{Snapshot: snapshotName(projectID, req.SnapshotID.String())}
	}
	created, err := c.volumes.CreateVolume(ctx, &storagev1.CreateVolumeRequest{
		Parent:    volumeParent(projectID),
		VolumeId:  derivedID("vol-", m.Key, "blank"),
		RequestId: requestUUID(m.Key, "blank-vol"),
		Volume: &storagev1.Volume{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   spec,
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return acceptedVolume(created, req, resource.VolumeCreating)
}

func (c computeClient) AttachVolume(ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.VolumeID.String())
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	instName := instanceName(projectID, req.InstanceID.String())
	inst, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: instName})
	if err != nil {
		return resource.Accepted[resource.Volume]{}, fromNamedRPC(instName, err)
	}
	volumes := append([]*computev1.VolumeAttachment{}, inst.GetSpec().GetVolumes()...)
	volumes = append(volumes, &computev1.VolumeAttachment{
		Volume:     volumeName(projectID, req.VolumeID.String()),
		DeviceName: req.Device,
	})
	updated, err := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
		RequestId:  requestUUID(m.Key, "attach"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.volumes", "labels"}},
		Instance: &computev1.Instance{
			Name: instanceName(projectID, req.InstanceID.String()),
			Labels: map[string]string{
				labelAction:      resource.ActionAttachVolume.String(),
				labelFingerprint: clip(m.Fingerprint, 63),
			},
			Spec: &computev1.InstanceSpec{Volumes: volumes},
		},
	})
	if err := rpcErr(updated, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	op, err := operationFrom(updated, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol.State = resource.VolumeInUse
	vol.InstanceID = req.InstanceID
	vol.Device = req.Device
	op.Action = resource.ActionAttachVolume
	op.Targets = []resource.Ref{vol.ID.Ref()}
	return resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}, nil
}

func (c computeClient) DeleteVolume(ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	deleted, err := c.volumes.DeleteVolume(ctx, &storagev1.DeleteVolumeRequest{
		Name:      volumeName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "delete-vol"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol.State = resource.VolumeDeleting
	op.Action = resource.ActionDeleteVolume
	op.Targets = []resource.Ref{vol.ID.Ref()}
	return resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}, nil
}

func (c computeClient) DescribeVolumes(ctx context.Context, s backend.Scope, q resource.VolumeQuery) (resource.Page[resource.Volume], error) {
	projectID := project(s.Account)
	if len(q.IDs) > 0 {
		items := make([]resource.Volume, 0, len(q.IDs))
		for _, id := range q.IDs {
			vol, err := c.getVolume(ctx, projectID, id.String())
			if resource.CodeOf(err) == resource.CodeNotFound {
				if len(q.IDs) == 1 {
					return resource.Page[resource.Volume]{}, err
				}
				continue
			}
			if err != nil {
				return resource.Page[resource.Volume]{}, err
			}
			items = append(items, vol)
		}
		return pageByID(items, q.Page, func(item resource.Volume) string { return item.ID.String() })
	}
	out, err := c.volumes.ListVolumes(ctx, &storagev1.ListVolumesRequest{
		Parent: volumeParent(projectID), PageSize: pageSize(q.Page.Size), PageToken: q.Page.Token,
	})
	if err != nil {
		return resource.Page[resource.Volume]{}, fromRPC(err)
	}
	items := make([]resource.Volume, 0, len(out.GetVolumes()))
	for _, item := range out.GetVolumes() {
		if sourcedVolume(item) {
			continue
		}
		vol, err := volumeModel(item)
		if err != nil {
			return resource.Page[resource.Volume]{}, err
		}
		items = append(items, vol)
	}
	return resource.Page[resource.Volume]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

func (c computeClient) DescribeImages(ctx context.Context, s backend.Scope, q resource.ImageQuery) (resource.Page[resource.Image], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Image]{}, err
	}
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Image
	for _, img := range resource.KnownImages(s.Account) {
		if len(want) > 0 {
			if _, ok := want[img.ID.String()]; !ok {
				continue
			}
		}
		items = append(items, img)
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Image]{}, resource.NotFound(resource.KindImage, q.IDs[0].String())
	}
	return pageByID(items, q.Page, func(item resource.Image) string { return item.ID.String() })
}

func (c computeClient) CreateKeyPair(ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	privateKey, fingerprint, publicLine, err := derivedKey(m.Key, "key-seed")
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	projectID := project(m.Account)
	labels := nameLabels(req.Name)
	labels[labelFingerprint] = clip(m.Fingerprint, 63)
	created, err := c.keys.CreateKeyPair(ctx, &computev1.CreateKeyPairRequest{
		Parent:    regionParent(projectID),
		KeyPairId: derivedID("key-", m.Key, "key"),
		RequestId: requestUUID(m.Key, "key"),
		KeyPair: &computev1.KeyPair{
			Labels: labels,
			Spec:   &computev1.KeyPairSpec{PublicKey: publicLine},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	op, err := operationFrom(created, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	id, err := resource.Parse[resource.KeyPairID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	key := resource.KeyPair{
		ID: id, OwnerID: owner, Name: req.Name, Fingerprint: fingerprint, Material: privateKey,
	}
	op.Action = resource.ActionCreateKeyPair
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{key}}, nil
}

func (c networkClient) CreateVpc(ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error) {
	projectID := project(m.Account)
	created, err := c.vpcs.CreateVpc(ctx, &networkv1.CreateVpcRequest{
		Parent:    regionParent(projectID),
		VpcId:     derivedID("vpc-", m.Key, "vpc"),
		RequestId: requestUUID(m.Key, "user-vpc"),
		Vpc: &networkv1.Vpc{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   &networkv1.VpcSpec{Ipv4Cidr: req.Cidr},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	id, err := resource.Parse[resource.VpcID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	vpc := resource.Vpc{ID: id, OwnerID: owner, Cidr: req.Cidr, State: resource.VpcPending}
	op.Action = resource.ActionCreateVpc
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{vpc}}, nil
}

func (c networkClient) DeleteVpc(ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest) (resource.Accepted[resource.Vpc], error) {
	projectID := project(m.Account)
	vpc, err := c.getVpc(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	deleted, err := c.vpcs.DeleteVpc(ctx, &networkv1.DeleteVpcRequest{
		Name:      vpcName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "delete-vpc"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	vpc.State = resource.VpcDeleting
	op.Action = resource.ActionDeleteVpc
	op.Targets = []resource.Ref{vpc.ID.Ref()}
	return resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{vpc}}, nil
}

func (c networkClient) DescribeVpcs(ctx context.Context, s backend.Scope, q resource.VpcQuery) (resource.Page[resource.Vpc], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 {
		vpc, err := c.getVpc(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.Vpc]{}, err
		}
		return pageByID([]resource.Vpc{vpc}, q.Page, func(item resource.Vpc) string { return item.ID.String() })
	}
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Vpc
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.Page[resource.Vpc]{}, fromRPC(err)
		}
		for _, item := range out.GetVpcs() {
			idText := lastSegment(item.GetName())
			if _, err := resource.Parse[resource.VpcID](idText); err != nil {
				continue
			}
			if len(want) > 0 {
				if _, ok := want[idText]; !ok {
					continue
				}
			}
			vpc, err := c.getVpc(ctx, projectID, idText)
			if resource.CodeOf(err) == resource.CodeNotFound {
				continue
			}
			if err != nil {
				return resource.Page[resource.Vpc]{}, err
			}
			items = append(items, vpc)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Vpc]{}, resource.NotFound(resource.KindVpc, q.IDs[0].String())
	}
	return pageByID(items, q.Page, func(item resource.Vpc) string { return item.ID.String() })
}

func (c networkClient) CreateSecurityGroup(ctx context.Context, m backend.Mutation, req resource.CreateSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	projectID := project(m.Account)
	created, err := c.groups.CreateSecurityGroup(ctx, &networkv1.CreateSecurityGroupRequest{
		Parent:          vpcName(projectID, req.VpcID.String()),
		SecurityGroupId: derivedID("sg-", m.Key, "sg"),
		RequestId:       requestUUID(m.Key, "sg"),
		SecurityGroup: &networkv1.SecurityGroup{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   &networkv1.SecurityGroupSpec{Description: req.Name},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	id, err := resource.Parse[resource.SecurityGroupID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	group := resource.SecurityGroup{ID: id, OwnerID: owner, Name: req.Name, VpcID: req.VpcID}
	op.Action = resource.ActionCreateSecurityGroup
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{group}}, nil
}

func (c networkClient) AuthorizeSecurityGroupIngress(ctx context.Context, m backend.Mutation, req resource.AuthorizeSecurityGroupIngressRequest) (resource.Accepted[resource.SecurityGroup], error) {
	projectID := project(m.Account)
	current, err := c.findGroup(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	for _, have := range current.Rules {
		if have == req.Rule {
			return resource.Accepted[resource.SecurityGroup]{}, resource.AlreadyExists(resource.KindSecurityGroup, current.ID.String())
		}
	}
	rules := append(append([]resource.IngressRule{}, current.Rules...), req.Rule)
	protoRules := make([]*networkv1.SecurityGroupRule, 0, len(rules))
	for i, rule := range rules {
		protoRule, err := ruleProto(rule, derivedID("r", m.Key, "rule", hex.EncodeToString([]byte{byte(i)})))
		if err != nil {
			return resource.Accepted[resource.SecurityGroup]{}, err
		}
		protoRules = append(protoRules, protoRule)
	}
	updated, err := c.groups.UpdateSecurityGroup(ctx, &networkv1.UpdateSecurityGroupRequest{
		RequestId:  requestUUID(m.Key, "ingress"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.rules"}},
		SecurityGroup: &networkv1.SecurityGroup{
			Name: securityGroupName(projectID, current.VpcID.String(), current.ID.String()),
			Spec: &networkv1.SecurityGroupSpec{Rules: protoRules},
		},
	})
	if err := rpcErr(updated, err); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op, err := operationFrom(updated, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	got, err := c.findGroup(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op.Action = resource.ActionAuthorizeSecurityGroupIngress
	op.Targets = []resource.Ref{got.ID.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{got}}, nil
}

func (c computeClient) getVolume(ctx context.Context, projectID, id string) (resource.Volume, error) {
	name := volumeName(projectID, id)
	out, err := c.volumes.GetVolume(ctx, &storagev1.GetVolumeRequest{Name: name})
	if err != nil {
		return resource.Volume{}, fromNamedRPC(name, err)
	}
	if sourcedVolume(out) {
		return resource.Volume{}, resource.NotFound(resource.KindVolume, id)
	}
	return volumeModel(out)
}

func (c networkClient) getVpc(ctx context.Context, projectID, id string) (resource.Vpc, error) {
	name := vpcName(projectID, id)
	out, err := c.vpcs.GetVpc(ctx, &networkv1.GetVpcRequest{Name: name})
	if err != nil {
		return resource.Vpc{}, fromNamedRPC(name, err)
	}
	return vpcModel(out)
}

func (c networkClient) findGroup(ctx context.Context, projectID, id string) (resource.SecurityGroup, error) {
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.SecurityGroup{}, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			got, err := c.groups.GetSecurityGroup(ctx, &networkv1.GetSecurityGroupRequest{
				Name: vpc.GetName() + "/securityGroups/" + id,
			})
			if err != nil {
				if resource.CodeOf(fromRPC(err)) == resource.CodeNotFound {
					continue
				}
				return resource.SecurityGroup{}, fromRPC(err)
			}
			return groupModel(got)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return resource.SecurityGroup{}, resource.NotFound(resource.KindSecurityGroup, id)
}

func acceptedVolume(op *longrunningpb.Operation, req resource.CreateVolumeRequest, state resource.VolumeState) (resource.Accepted[resource.Volume], error) {
	parsed, err := operationFrom(op, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	metaName, err := metadataResource(op)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	id, err := resource.Parse[resource.VolumeID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Volume]{}, resource.Internal(err)
	}
	named, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol := resource.Volume{ID: id, OwnerID: named, SizeGiB: req.SizeGiB, Zone: req.Zone, Type: req.Type, State: state, SnapshotID: req.SnapshotID, CreateTime: parsed.CreateTime}
	parsed.Action = resource.ActionCreateVolume
	parsed.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Volume]{Operation: parsed, Items: []resource.Volume{vol}}, nil
}

func nameLabels(name string) map[string]string {
	keys := []string{"keyname", "keyname2", "keyname3", "keyname4", "keyname5"}
	out := map[string]string{}
	for i, key := range keys {
		start := i * 63
		if start >= len(name) {
			break
		}
		end := start + 63
		if end > len(name) {
			end = len(name)
		}
		out[key] = name[start:end]
	}
	return out
}

func stateRefs(items []resource.InstanceStateChange) []resource.Ref {
	out := make([]resource.Ref, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID.Ref())
	}
	return out
}

func volumeModel(in *storagev1.Volume) (resource.Volume, error) {
	if in == nil {
		return resource.Volume{}, resource.Internal(errors.New("missing volume"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "volumes" {
		return resource.Volume{}, resource.Internal(errors.New("bad volume name"))
	}
	id, err := resource.Parse[resource.VolumeID](parts[5])
	if err != nil {
		return resource.Volume{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Volume{}, err
	}
	state, err := volumeStateOf(in)
	if err != nil {
		return resource.Volume{}, err
	}
	var inst resource.InstanceID
	if name := in.GetStatus().GetInstance(); name != "" {
		parsed, err := resource.Parse[resource.InstanceID](lastSegment(name))
		if err != nil {
			return resource.Volume{}, resource.Internal(err)
		}
		inst = parsed
	}
	var snap resource.SnapshotID
	if name := in.GetSpec().GetSnapshot(); name != "" {
		parsed, err := resource.Parse[resource.SnapshotID](lastSegment(name))
		if err != nil {
			return resource.Volume{}, resource.Internal(err)
		}
		snap = parsed
	}
	return resource.Volume{
		ID: id, OwnerID: owner, SizeGiB: in.GetSpec().GetSizeGib(), Zone: parts[3], SnapshotID: snap,
		Type: volumeTypeOf(in.GetSpec().GetType()), State: state, InstanceID: inst, Device: in.GetStatus().GetDeviceName(),
		CreateTime: in.GetCreateTime().AsTime().UTC(),
	}, nil
}

func volumeStateOf(in *storagev1.Volume) (resource.VolumeState, error) {
	if in.GetStatus().GetInstance() != "" {
		return resource.VolumeInUse, nil
	}
	switch in.GetStatus().GetObserved().GetState() {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.VolumeCreating, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.VolumeAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.VolumeDeleting, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return "", resource.Internal(errors.New("bad volume state"))
	default:
		return "", resource.Internal(errors.New("bad volume state"))
	}
}

func volumeProto(v resource.Volume, projectID string) *storagev1.Volume {
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	switch v.State {
	case resource.VolumeAvailable, resource.VolumeInUse:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	case resource.VolumeDeleting:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING
	case resource.VolumeCreating:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	}
	status := &storagev1.VolumeStatus{
		Observed:   &commonv1.ObservedState{State: obs},
		DeviceName: v.Device,
	}
	if !v.InstanceID.IsZero() {
		status.Instance = instanceName(projectID, v.InstanceID.String())
	}
	var created *timestamppb.Timestamp
	if !v.CreateTime.IsZero() {
		created = timestamppb.New(v.CreateTime)
	}
	spec := &storagev1.VolumeSpec{SizeGib: v.SizeGiB, Type: storagev1.VolumeType_VOLUME_TYPE_SSD}
	if !v.SnapshotID.IsZero() {
		spec.Source = &storagev1.VolumeSpec_Snapshot{Snapshot: snapshotName(projectID, v.SnapshotID.String())}
	}
	return &storagev1.Volume{
		CreateTime: created,
		Name:       volumeName(projectID, v.ID.String()),
		Spec:       spec,
		Status:     status,
	}
}

func vpcModel(in *networkv1.Vpc) (resource.Vpc, error) {
	if in == nil {
		return resource.Vpc{}, resource.Internal(errors.New("missing vpc"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "vpcs" {
		return resource.Vpc{}, resource.Internal(errors.New("bad vpc name"))
	}
	id, err := resource.Parse[resource.VpcID](parts[5])
	if err != nil {
		return resource.Vpc{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Vpc{}, err
	}
	state, err := vpcStateOf(in.GetStatus().GetObserved().GetState())
	if err != nil {
		return resource.Vpc{}, err
	}
	return resource.Vpc{ID: id, OwnerID: owner, Cidr: in.GetSpec().GetIpv4Cidr(), State: state}, nil
}

func vpcStateOf(obs commonv1.ReconciliationState) (string, error) {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.VpcPending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.VpcAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.VpcDeleting, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return "", resource.Internal(errors.New("bad vpc state"))
	default:
		return "", resource.Internal(errors.New("bad vpc state"))
	}
}

func vpcProto(v resource.Vpc, projectID string) *networkv1.Vpc {
	return &networkv1.Vpc{
		Name:   vpcName(projectID, v.ID.String()),
		Spec:   &networkv1.VpcSpec{Ipv4Cidr: v.Cidr},
		Status: &networkv1.VpcStatus{Observed: &commonv1.ObservedState{State: vpcObserved(v.State)}},
	}
}

func vpcObserved(state string) commonv1.ReconciliationState {
	switch state {
	case resource.VpcAvailable:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	case resource.VpcDeleting:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING
	default:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	}
}

func groupModel(in *networkv1.SecurityGroup) (resource.SecurityGroup, error) {
	if in == nil {
		return resource.SecurityGroup{}, resource.Internal(errors.New("missing security group"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 8 || parts[6] != "securityGroups" {
		return resource.SecurityGroup{}, resource.Internal(errors.New("bad security group name"))
	}
	id, err := resource.Parse[resource.SecurityGroupID](parts[7])
	if err != nil {
		return resource.SecurityGroup{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.SecurityGroup{}, err
	}
	vpcID, err := resource.Parse[resource.VpcID](parts[5])
	if err != nil {
		return resource.SecurityGroup{}, resource.Internal(err)
	}
	var rules []resource.IngressRule
	for _, rule := range in.GetSpec().GetRules() {
		if rule.GetDirection() != networkv1.Direction_DIRECTION_INGRESS {
			continue
		}
		rules = append(rules, resource.IngressRule{
			Protocol: protocolName(rule.GetProtocol()),
			FromPort: int(rule.GetFromPort()),
			ToPort:   int(rule.GetToPort()),
			Cidr:     rule.GetCidr(),
		})
	}
	return resource.SecurityGroup{
		ID: id, OwnerID: owner, Name: in.GetSpec().GetDescription(), VpcID: vpcID, Rules: rules,
	}, nil
}

func protocolOf(name string) (networkv1.Protocol, error) {
	switch name {
	case "tcp":
		return networkv1.Protocol_PROTOCOL_TCP, nil
	case "udp":
		return networkv1.Protocol_PROTOCOL_UDP, nil
	case "icmp":
		return networkv1.Protocol_PROTOCOL_ICMP, nil
	case "-1", "all":
		return networkv1.Protocol_PROTOCOL_ALL, nil
	default:
		return networkv1.Protocol_PROTOCOL_UNSPECIFIED, resource.Invalid("ipProtocol", "unsupported")
	}
}

func ruleProto(rule resource.IngressRule, id string) (*networkv1.SecurityGroupRule, error) {
	protocol, err := protocolOf(rule.Protocol)
	if err != nil {
		return nil, err
	}
	return &networkv1.SecurityGroupRule{
		Id:        id,
		Direction: networkv1.Direction_DIRECTION_INGRESS,
		Protocol:  protocol,
		FromPort:  int32(rule.FromPort),
		ToPort:    int32(rule.ToPort),
		Target:    &networkv1.SecurityGroupRule_Cidr{Cidr: rule.Cidr},
	}, nil
}

// sourcedVolume reports a boot volume, which RunInstances creates from an
// image. A volume restored from a snapshot is a DescribeVolumes row.
func sourcedVolume(in *storagev1.Volume) bool {
	return in.GetSpec().GetImage() != ""
}

func protocolName(p networkv1.Protocol) string {
	switch p {
	case networkv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case networkv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case networkv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	case networkv1.Protocol_PROTOCOL_ALL:
		return "-1"
	case networkv1.Protocol_PROTOCOL_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// derivedKey's domain is "key-seed". The key id and the request id use a
// different domain, so neither published value is the private key.
func derivedKey(parts ...string) (string, string, string, error) {
	sum := hashParts(parts...)
	priv := ed25519.NewKeyFromSeed(sum[:ed25519.SeedSize])
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", resource.Internal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", "", resource.Internal(errors.New("ed25519 public key"))
	}
	fp := sha256.Sum256(pub)
	return string(block), hex.EncodeToString(fp[:]), sshEd25519(pub), nil
}

func sshEd25519(pub ed25519.PublicKey) string {
	payload := sshString("ssh-ed25519") + sshString(string(pub))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(payload))
}

func sshString(s string) string {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(s)))
	return string(size[:]) + s
}

// storageType maps an EC2 volume type to the storage tier. The storage proto
// has only STANDARD and SSD, so gp2 and gp3 both land on SSD.
func storageType(t resource.VolumeType) storagev1.VolumeType {
	if t == resource.VolumeStandard {
		return storagev1.VolumeType_VOLUME_TYPE_STANDARD
	}
	return storagev1.VolumeType_VOLUME_TYPE_SSD
}

// volumeTypeOf reports an SSD volume as gp2 because storage does not keep
// which SSD type was asked for.
func volumeTypeOf(t storagev1.VolumeType) resource.VolumeType {
	if t == storagev1.VolumeType_VOLUME_TYPE_STANDARD {
		return resource.VolumeStandard
	}
	return resource.VolumeGP2
}
