package ec2query

import (
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// queryKey is one EC2 Query key shape an action accepts. The pattern is
// dot-separated; each "N" segment is an index from 1 to the next entry of
// bounds, spelled as strconv.Itoa spells it. Every other segment is literal.
// Keeping the accepted keys as data lets a test list exactly what an action
// takes and compare it with the AWS EC2 model (#882).
type queryKey struct {
	pattern string
	bounds  []int
}

func literal(names ...string) []queryKey {
	out := make([]queryKey, 0, len(names))
	for _, n := range names {
		out = append(out, queryKey{pattern: n})
	}
	return out
}

func indexedKey(pattern string, bounds ...int) queryKey {
	return queryKey{pattern: pattern, bounds: bounds}
}

func (k queryKey) matches(key string) bool {
	pattern, b := k.pattern, 0
	for {
		seg, prest, pmore := strings.Cut(pattern, ".")
		part, krest, kmore := strings.Cut(key, ".")
		if seg == "N" {
			if !inRange(part, k.bounds[b]) {
				return false
			}
			b++
		} else if seg != part {
			return false
		}
		if pmore != kmore {
			return false
		}
		if !pmore {
			return true
		}
		pattern, key = prest, krest
	}
}

func acceptsKey(keys []queryKey, key string) bool {
	return slices.ContainsFunc(keys, func(k queryKey) bool { return k.matches(key) })
}

// queryKeys are the keys action accepts; rejectUnknown refuses every other.
func queryKeys(action string) []queryKey {
	common := literal("Action", "Version")
	token := literal("Action", "Version", "ClientToken")
	switch action {
	case resource.ActionRunInstances.String():
		return slices.Concat(
			literal("Action", "Version", "ImageId", "InstanceType", "SubnetId", "MinCount", "MaxCount",
				"ClientToken", "KeyName", "UserData"),
			tagKeys(20), tagSpecKeys(), blockDeviceKeys(), networkInterfaceKeys())
	case resource.ActionStopInstances.String(), resource.ActionStartInstances.String(),
		resource.ActionTerminateInstances.String():
		return append(token, indexedKey("InstanceId.N", 100))
	case resource.ActionRebootInstances.String():
		return append(common, indexedKey("InstanceId.N", 100))
	case resource.ActionCreateSubnet.String():
		return slices.Concat(token, literal("CidrBlock", "VpcId", "AvailabilityZone"), tagSpecKeys())
	case resource.ActionCreateVpc.String():
		return slices.Concat(token, literal("CidrBlock", "InstanceTenancy"), tagSpecKeys())
	case resource.ActionDeleteVpc.String():
		return append(token, literal("VpcId")...)
	case resource.ActionCreateVolume.String():
		return slices.Concat(token,
			literal("Size", "AvailabilityZone", "VolumeType", "SnapshotId", "Iops", "Throughput"), tagSpecKeys())
	case resource.ActionAttachVolume.String():
		return append(token, literal("VolumeId", "InstanceId", "Device")...)
	case resource.ActionDetachVolume.String():
		return append(token, literal("VolumeId", "InstanceId", "Device", "Force")...)
	case resource.ActionDeleteVolume.String():
		return append(token, literal("VolumeId")...)
	case resource.ActionModifyVolume.String():
		return append(common, literal("VolumeId", "Size", "VolumeType", "Iops", "Throughput")...)
	case resource.ActionCreateTags.String():
		return slices.Concat(token, []queryKey{indexedKey("ResourceId.N", 20)}, tagKeys(50))
	case resource.ActionDeleteTags.String():
		// CreateTags without ClientToken, which EC2 DeleteTags does not take.
		return slices.Concat(common, []queryKey{indexedKey("ResourceId.N", 20)}, tagKeys(maxDeleteTagIndex))
	case resource.ActionCreateSecurityGroup.String():
		return append(token, literal("GroupName", "GroupDescription", "VpcId")...)
	case resource.ActionAuthorizeSecurityGroupIngress.String(), resource.ActionRevokeSecurityGroupIngress.String():
		return ingressKeys()
	case resource.ActionCreateKeyPair.String():
		return slices.Concat(token, literal("KeyName", "KeyType", "KeyFormat"), tagSpecKeys())
	case resource.ActionDeleteKeyPair.String():
		return append(token, literal("KeyName", "KeyPairId")...)
	case "ImportKeyPair":
		return slices.Concat(common, literal("KeyName", "PublicKeyMaterial"), tagSpecKeys())
	case "DescribeInstanceAttribute":
		return append(common, literal("InstanceId", "Attribute", "DryRun")...)
	case resource.ActionDeleteSecurityGroup.String():
		return append(token, literal("GroupId", "GroupName")...)
	case resource.ActionDeleteSubnet.String():
		return append(token, literal("SubnetId")...)
	case resource.ActionAllocateAddress.String():
		return append(token, literal("Domain")...)
	case resource.ActionReleaseAddress.String():
		return append(token, literal("AllocationId")...)
	case resource.ActionCreateSnapshot.String():
		return slices.Concat(token, literal("VolumeId", "Description"), tagSpecKeys())
	case resource.ActionDeleteSnapshot.String():
		return append(token, literal("SnapshotId")...)
	case resource.ActionRegisterImage.String():
		return append(token, literal("Name", "Description", "Architecture", "VirtualizationType", "EnaSupport",
			"RootDeviceName", registerDevice, registerSnapshot, registerDeleteOnEnd)...)
	case resource.ActionAssociateAddress.String():
		return append(token, literal("AllocationId", "InstanceId")...)
	case resource.ActionDisassociateAddress.String():
		return append(token, literal("AssociationId")...)
	case "DescribeInstances":
		return describeKeys(indexedKey("InstanceId.N", 100))
	case "DescribeSubnets":
		return describeKeys(indexedKey("SubnetId.N", 100))
	case "DescribeVpcs":
		return describeKeys(indexedKey("VpcId.N", 100))
	case "DescribeVolumes":
		return describeKeys(indexedKey("VolumeId.N", 100))
	case "DescribeImages":
		return describeKeys(append([]queryKey{
			indexedKey("ImageId.N", 100), indexedKey("Owner.N", 100), indexedKey("OwnerId.N", 100),
			indexedKey("ExecutableBy.N", 100),
		}, literal("IncludeDeprecated", "IncludeDisabled")...)...)
	case "DescribeKeyPairs":
		return describeKeys(append([]queryKey{indexedKey("KeyName.N", 100), indexedKey("KeyPairId.N", 100)},
			literal("IncludePublicKey")...)...)
	case "DescribeSecurityGroups":
		return describeKeys(indexedKey("GroupId.N", 100), indexedKey("GroupName.N", 100))
	case "DescribeAddresses":
		return describeKeys(indexedKey("AllocationId.N", 100), indexedKey("PublicIp.N", 100))
	case "DescribeSnapshots":
		return describeKeys(indexedKey("SnapshotId.N", 100), indexedKey("Owner.N", 100),
			indexedKey("OwnerId.N", 100), indexedKey("RestorableBy.N", 100))
	case "DescribeInstanceStatus":
		return describeKeys(append([]queryKey{indexedKey("InstanceId.N", 100)},
			literal("IncludeAllInstances", "includeAllInstances", "IncludeManagedResources",
				"includeManagedResources")...)...)
	case "DescribeInstanceTypes":
		return describeKeys(append([]queryKey{indexedKey("InstanceType.N", 100)},
			literal("IncludeUnsupportedInRegion", "includeUnsupportedInRegion")...)...)
	case "DescribeTags":
		return describeKeys()
	case "DescribeVolumesModifications":
		return describeKeys(append([]queryKey{indexedKey("VolumeId.N", 100)},
			literal("IncludeManagedResources", "includeManagedResources")...)...)
	case "DescribeAvailabilityZones":
		return slices.Concat(unpagedDescribeKeys(),
			[]queryKey{indexedKey("ZoneName.N", 100), indexedKey("ZoneId.N", 100)},
			literal("AllAvailabilityZones"))
	case "DescribeRegions":
		return slices.Concat(unpagedDescribeKeys(), []queryKey{indexedKey("RegionName.N", 100)},
			literal("AllRegions"))
	case "DescribeRouteTables":
		return describeKeys(indexedKey("RouteTableId.N", 100))
	default:
		return common
	}
}

func describeKeys(extra ...queryKey) []queryKey {
	return slices.Concat(literal("MaxResults", "maxResults", "NextToken", "nextToken"), unpagedDescribeKeys(), extra)
}

// unpagedDescribeKeys is the describe shape without pagination.
func unpagedDescribeKeys() []queryKey {
	return append(literal("Action", "Version", "DryRun", "dryRun"),
		indexedKey("Filter.N.Name", 20), indexedKey("Filter.N.Value.N", 20, filterValueMax))
}

func tagKeys(limit int) []queryKey {
	return []queryKey{indexedKey("Tag.N.Key", limit), indexedKey("Tag.N.Value", limit)}
}

func tagSpecKeys() []queryKey {
	return []queryKey{
		indexedKey("TagSpecification.N.ResourceType", 5),
		indexedKey("TagSpecification.N.Tag.N.Key", 5, resource.MaxTags),
		indexedKey("TagSpecification.N.Tag.N.Value", 5, resource.MaxTags),
	}
}

// blockDeviceKeys are the BlockDeviceMapping.N fields blockDeviceMappings
// reads or refuses by name.
func blockDeviceKeys() []queryKey {
	var out []queryKey
	for _, field := range mappingFields() {
		out = append(out, indexedKey("BlockDeviceMapping.N."+field, maxBlockDeviceMappings))
	}
	for _, u := range unsupportedDeviceFields() {
		if !slices.Contains(mappingFields(), u.field) {
			out = append(out, indexedKey("BlockDeviceMapping.N."+u.field, maxBlockDeviceMappings))
		}
	}
	return out
}

// networkInterfaceKeys are the NetworkInterface.N fields networkInterfaces
// reads, so no member is accepted and then skipped.
func networkInterfaceKeys() []queryKey {
	var out []queryKey
	for _, field := range networkInterfaceFields() {
		out = append(out, indexedKey("NetworkInterface.N."+field, resource.MaxNetworkInterfaces))
	}
	return out
}

// ingressKeys is the IpPermissions list AuthorizeSecurityGroupIngress and
// RevokeSecurityGroupIngress take, plus the top-level single-rule fields.
func ingressKeys() []queryKey {
	out := literal("Action", "Version", "ClientToken", "GroupId", "IpProtocol", "FromPort", "ToPort", "CidrIp")
	for _, leaf := range []string{"IpProtocol", "FromPort", "ToPort"} {
		out = append(out, indexedKey("IpPermissions.N."+leaf, maxQueryIndex))
	}
	sources := []struct {
		list   string
		leaves []string
	}{
		{"IpRanges", []string{"CidrIp", "Description"}},
		{"Ipv6Ranges", []string{"CidrIpv6", "Description"}},
		{"PrefixListIds", []string{"PrefixListId", "Description"}},
		// The query names the UserIdGroupPairs member Groups.
		{"Groups", []string{
			"Description", "GroupId", "GroupName", "PeeringStatus", "UserId", "VpcId",
			"VpcPeeringConnectionId",
		}},
	}
	for _, s := range sources {
		for _, leaf := range s.leaves {
			out = append(out, indexedKey("IpPermissions.N."+s.list+".N."+leaf, maxQueryIndex, maxQueryIndex))
		}
	}
	return out
}
