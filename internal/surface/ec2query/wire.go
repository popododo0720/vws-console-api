package ec2query

import (
	"encoding/xml"
	"maps"
	"slices"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type runInstancesXML struct {
	XMLName       struct{}    `xml:"RunInstancesResponse"`
	RequestID     string      `xml:"requestId"`
	ReservationID string      `xml:"reservationId"`
	Instances     instanceSet `xml:"instancesSet"`
}

type describeInstancesXML struct {
	XMLName      struct{} `xml:"DescribeInstancesResponse"`
	RequestID    string   `xml:"requestId"`
	NextToken    string   `xml:"nextToken,omitempty"`
	Reservations struct {
		Items []reservationItem `xml:"item"`
	} `xml:"reservationSet"`
}

type reservationItem struct {
	ReservationID string      `xml:"reservationId"`
	OwnerID       string      `xml:"ownerId"`
	Instances     instanceSet `xml:"instancesSet"`
}

type instanceSet struct {
	Items []instanceItem `xml:"item"`
}

type instanceItem struct {
	InstanceID   string          `xml:"instanceId"`
	ImageID      string          `xml:"imageId"`
	InstanceType string          `xml:"instanceType"`
	KeyName      string          `xml:"keyName,omitempty"`
	SubnetID     string          `xml:"subnetId"`
	VpcID        string          `xml:"vpcId,omitempty"`
	LaunchTime   string          `xml:"launchTime,omitempty"`
	PublicIP     string          `xml:"ipAddress,omitempty"`
	NICs         *nicSet         `xml:"networkInterfaceSet,omitempty"`
	Zone         string          `xml:"placement>availabilityZone"`
	PrivateIP    string          `xml:"privateIpAddress,omitempty"`
	State        stateXML        `xml:"instanceState"`
	Reason       *stateReasonXML `xml:"stateReason,omitempty"`
	Tags         *tagSet         `xml:"tagSet,omitempty"`
	RootDevice   string          `xml:"rootDeviceName,omitempty"`
	RootType     string          `xml:"rootDeviceType,omitempty"`
	Blocks       *blockSet       `xml:"blockDeviceMapping,omitempty"`
}

type blockSet struct {
	Items []blockItem `xml:"item"`
}

type blockItem struct {
	Device string `xml:"deviceName"`
	EBS    struct {
		VolumeID            string `xml:"volumeId"`
		Status              string `xml:"status"`
		AttachTime          string `xml:"attachTime,omitempty"`
		DeleteOnTermination bool   `xml:"deleteOnTermination"`
	} `xml:"ebs"`
}

func blockSetOf(inst resource.Instance) *blockSet {
	if len(inst.BlockDevices) == 0 {
		return nil
	}
	out := &blockSet{}
	for _, b := range inst.BlockDevices {
		item := blockItem{Device: b.Device}
		// The backend reports attached only once the disk is on the machine;
		// an unset status is never shown as attached (#448). EC2
		// EbsInstanceBlockDevice.Status has no busy: a block device is in the
		// instance spec, so a busy one is a plug the node is retrying.
		status := b.Status
		if status == "" || status == resource.AttachmentBusy {
			status = resource.AttachmentAttaching
		}
		item.EBS.VolumeID, item.EBS.Status = b.VolumeID.String(), string(status)
		item.EBS.DeleteOnTermination = b.DeleteOnTermination
		item.EBS.AttachTime = awsTime(attachTimeOr(b.AttachTime, inst.LaunchTime))
		out.Items = append(out.Items, item)
	}
	return out
}

type nicSet struct {
	Items []nicItem `xml:"item"`
}

// nicItem is the instance's one network interface. VWS has no separate
// interface id, so only the fields the console reads are set.
type nicItem struct {
	SubnetID    string          `xml:"subnetId,omitempty"`
	VpcID       string          `xml:"vpcId,omitempty"`
	OwnerID     string          `xml:"ownerId,omitempty"`
	PrivateIP   string          `xml:"privateIpAddress,omitempty"`
	Association *nicAssociation `xml:"association,omitempty"`
}

type nicAssociation struct {
	PublicIP      string `xml:"publicIp"`
	IPOwnerID     string `xml:"ipOwnerId,omitempty"`
	AllocationID  string `xml:"allocationId,omitempty"`
	AssociationID string `xml:"associationId,omitempty"`
}

type tagSet struct {
	Items []tagItem `xml:"item"`
}

type tagItem struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

// tagSetOf returns tags sorted by key, or nil when there are none.
func tagSetOf(tags map[string]string) *tagSet {
	if len(tags) == 0 {
		return nil
	}
	out := &tagSet{}
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		out.Items = append(out.Items, tagItem{Key: k, Value: tags[k]})
	}
	return out
}

type stateXML struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type stateReasonXML struct {
	Code    string `xml:"code"`
	Message string `xml:"message"`
}

type stopInstancesXML struct {
	XMLName   struct{} `xml:"StopInstancesResponse"`
	RequestID string   `xml:"requestId"`
	Instances struct {
		Items []stateItem `xml:"item"`
	} `xml:"instancesSet"`
}

type stateItem struct {
	InstanceID    string   `xml:"instanceId"`
	CurrentState  stateXML `xml:"currentState"`
	PreviousState stateXML `xml:"previousState"`
}

type createSubnetXML struct {
	XMLName   struct{}   `xml:"CreateSubnetResponse"`
	RequestID string     `xml:"requestId"`
	Subnet    subnetItem `xml:"subnet"`
}

type describeSubnetsXML struct {
	XMLName   struct{} `xml:"DescribeSubnetsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Subnets   struct {
		Items []subnetItem `xml:"item"`
	} `xml:"subnetSet"`
}

type subnetItem struct {
	SubnetID string  `xml:"subnetId"`
	VpcID    string  `xml:"vpcId,omitempty"`
	Cidr     string  `xml:"cidrBlock"`
	State    string  `xml:"state"`
	Zone     string  `xml:"availabilityZone,omitempty"`
	MapIP    bool    `xml:"mapPublicIpOnLaunch"`
	Tags     *tagSet `xml:"tagSet,omitempty"`
}

type createVpcXML struct {
	XMLName   struct{} `xml:"CreateVpcResponse"`
	RequestID string   `xml:"requestId"`
	Vpc       vpcItem  `xml:"vpc"`
}

type describeVpcsXML struct {
	XMLName   struct{} `xml:"DescribeVpcsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Vpcs      struct {
		Items []vpcItem `xml:"item"`
	} `xml:"vpcSet"`
}

type vpcItem struct {
	VpcID     string  `xml:"vpcId"`
	State     string  `xml:"state"`
	Cidr      string  `xml:"cidrBlock"`
	OwnerID   string  `xml:"ownerId"`
	IsDefault bool    `xml:"isDefault"`
	Tags      *tagSet `xml:"tagSet,omitempty"`
}

type deleteVpcXML struct {
	XMLName   struct{} `xml:"DeleteVpcResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type createVolumeXML struct {
	XMLName    struct{} `xml:"CreateVolumeResponse"`
	RequestID  string   `xml:"requestId"`
	VolumeID   string   `xml:"volumeId"`
	Size       int64    `xml:"size"`
	Zone       string   `xml:"availabilityZone"`
	Status     string   `xml:"status"`
	Type       string   `xml:"volumeType"`
	Snapshot   string   `xml:"snapshotId,omitempty"`
	Created    string   `xml:"createTime,omitempty"`
	Iops       int64    `xml:"iops,omitempty"`
	Throughput int64    `xml:"throughput,omitempty"`
}

type describeVolumesXML struct {
	XMLName   struct{} `xml:"DescribeVolumesResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Volumes   struct {
		Items []volumeItem `xml:"item"`
	} `xml:"volumeSet"`
}

type volumeItem struct {
	VolumeID    string `xml:"volumeId"`
	Size        int64  `xml:"size"`
	Zone        string `xml:"availabilityZone"`
	Status      string `xml:"status"`
	Type        string `xml:"volumeType"`
	Snapshot    string `xml:"snapshotId,omitempty"`
	Created     string `xml:"createTime,omitempty"`
	Iops        int64  `xml:"iops,omitempty"`
	Throughput  int64  `xml:"throughput,omitempty"`
	Attachments struct {
		Items []attachmentItem `xml:"item"`
	} `xml:"attachmentSet,omitempty"`
}

type attachmentItem struct {
	VolumeID   string `xml:"volumeId"`
	InstanceID string `xml:"instanceId"`
	Device     string `xml:"device"`
	Status     string `xml:"status"`
	AttachTime string `xml:"attachTime,omitempty"`
	// DeleteOnTermination is always written, as EC2 does.
	DeleteOnTermination bool `xml:"deleteOnTermination"`
}

type attachVolumeXML struct {
	XMLName    struct{} `xml:"AttachVolumeResponse"`
	RequestID  string   `xml:"requestId"`
	VolumeID   string   `xml:"volumeId"`
	InstanceID string   `xml:"instanceId"`
	Device     string   `xml:"device"`
	Status     string   `xml:"status"`
	AttachTime string   `xml:"attachTime,omitempty"`
}

type detachVolumeXML struct {
	XMLName    struct{} `xml:"DetachVolumeResponse"`
	RequestID  string   `xml:"requestId"`
	VolumeID   string   `xml:"volumeId"`
	InstanceID string   `xml:"instanceId"`
	Device     string   `xml:"device"`
	Status     string   `xml:"status"`
	AttachTime string   `xml:"attachTime,omitempty"`
}

type modifyVolumeXML struct {
	XMLName      struct{}              `xml:"ModifyVolumeResponse"`
	RequestID    string                `xml:"requestId"`
	Modification volumeModificationXML `xml:"volumeModification"`
}

type volumeModificationXML struct {
	VolumeID     string `xml:"volumeId"`
	State        string `xml:"modificationState"`
	TargetSize   int64  `xml:"targetSize"`
	OriginalSize int64  `xml:"originalSize"`
	TargetType   string `xml:"targetVolumeType"`
	OriginalType string `xml:"originalVolumeType"`
	Start        string `xml:"startTime"`
}

type createTagsXML struct {
	XMLName   struct{} `xml:"CreateTagsResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type deleteVolumeXML struct {
	XMLName   struct{} `xml:"DeleteVolumeResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type createGroupXML struct {
	XMLName   struct{} `xml:"CreateSecurityGroupResponse"`
	RequestID string   `xml:"requestId"`
	GroupID   string   `xml:"groupId"`
}

type authorizeXML struct {
	XMLName   struct{} `xml:"AuthorizeSecurityGroupIngressResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type revokeXML struct {
	XMLName   struct{} `xml:"RevokeSecurityGroupIngressResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type instancesChangedXML struct {
	XMLName   xml.Name
	RequestID string `xml:"requestId"`
	Instances struct {
		Items []stateItem `xml:"item"`
	} `xml:"instancesSet"`
}

type describeImagesXML struct {
	XMLName   struct{} `xml:"DescribeImagesResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Images    struct {
		Items []imageItem `xml:"item"`
	} `xml:"imagesSet"`
}

type imageItem struct {
	ImageID            string `xml:"imageId"`
	Name               string `xml:"name"`
	State              string `xml:"imageState"`
	OwnerID            string `xml:"imageOwnerId"`
	Architecture       string `xml:"architecture"`
	ImageType          string `xml:"imageType"`
	RootDeviceType     string `xml:"rootDeviceType"`
	VirtualizationType string `xml:"virtualizationType"`
	Public             bool   `xml:"isPublic"`
}

type createKeyXML struct {
	XMLName        struct{} `xml:"CreateKeyPairResponse"`
	RequestID      string   `xml:"requestId"`
	KeyName        string   `xml:"keyName"`
	KeyFingerprint string   `xml:"keyFingerprint"`
	KeyMaterial    string   `xml:"keyMaterial"`
	KeyPairID      string   `xml:"keyPairId"`
}

type deleteKeyXML struct {
	XMLName   struct{} `xml:"DeleteKeyPairResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type describeKeysXML struct {
	XMLName   struct{} `xml:"DescribeKeyPairsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Keys      struct {
		Items []keyItem `xml:"item"`
	} `xml:"keySet"`
}

type keyItem struct {
	KeyPairID   string `xml:"keyPairId"`
	KeyName     string `xml:"keyName"`
	Fingerprint string `xml:"keyFingerprint"`
	KeyType     string `xml:"keyType,omitempty"`
}

type importKeyXML struct {
	XMLName        struct{} `xml:"ImportKeyPairResponse"`
	RequestID      string   `xml:"requestId"`
	KeyFingerprint string   `xml:"keyFingerprint"`
	KeyName        string   `xml:"keyName"`
	KeyPairID      string   `xml:"keyPairId"`
}

type instanceAttributeXML struct {
	XMLName    struct{} `xml:"DescribeInstanceAttributeResponse"`
	RequestID  string   `xml:"requestId"`
	InstanceID string   `xml:"instanceId"`
	UserData   struct {
		Value string `xml:"value,omitempty"`
	} `xml:"userData"`
}

type deleteGroupXML struct {
	XMLName   struct{} `xml:"DeleteSecurityGroupResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type describeGroupsXML struct {
	XMLName   struct{} `xml:"DescribeSecurityGroupsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Groups    struct {
		Items []groupItem `xml:"item"`
	} `xml:"securityGroupInfo"`
}

type groupItem struct {
	GroupID       string           `xml:"groupId"`
	GroupName     string           `xml:"groupName"`
	VpcID         string           `xml:"vpcId,omitempty"`
	IPPermissions []permissionItem `xml:"ipPermissions>item,omitempty"`
}

type permissionItem struct {
	Protocol string     `xml:"ipProtocol"`
	FromPort int        `xml:"fromPort"`
	ToPort   int        `xml:"toPort"`
	IPRanges []cidrItem `xml:"ipRanges>item"`
}

type cidrItem struct {
	CidrIP string `xml:"cidrIp"`
}

type deleteSubnetXML struct {
	XMLName   struct{} `xml:"DeleteSubnetResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type allocateAddressXML struct {
	XMLName      struct{} `xml:"AllocateAddressResponse"`
	RequestID    string   `xml:"requestId"`
	PublicIP     string   `xml:"publicIp"`
	Domain       string   `xml:"domain,omitempty"`
	AllocationID string   `xml:"allocationId"`
}

type releaseAddressXML struct {
	XMLName   struct{} `xml:"ReleaseAddressResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type associateAddressXML struct {
	XMLName       struct{} `xml:"AssociateAddressResponse"`
	RequestID     string   `xml:"requestId"`
	Return        bool     `xml:"return"`
	AssociationID string   `xml:"associationId"`
}

type disassociateAddressXML struct {
	XMLName   struct{} `xml:"DisassociateAddressResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type describeAddressesXML struct {
	XMLName   struct{} `xml:"DescribeAddressesResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Addresses struct {
		Items []addressItem `xml:"item"`
	} `xml:"addressesSet"`
}

type addressItem struct {
	PublicIP      string `xml:"publicIp,omitempty"`
	Domain        string `xml:"domain,omitempty"`
	AllocationID  string `xml:"allocationId"`
	InstanceID    string `xml:"instanceId,omitempty"`
	AssociationID string `xml:"associationId,omitempty"`
}

type createSnapshotXML struct {
	XMLName     struct{} `xml:"CreateSnapshotResponse"`
	RequestID   string   `xml:"requestId"`
	SnapshotID  string   `xml:"snapshotId"`
	VolumeID    string   `xml:"volumeId"`
	Status      string   `xml:"status"`
	VolumeSize  int64    `xml:"volumeSize"`
	Description string   `xml:"description,omitempty"`
}

type deleteSnapshotXML struct {
	XMLName   struct{} `xml:"DeleteSnapshotResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type describeSnapshotsXML struct {
	XMLName   struct{} `xml:"DescribeSnapshotsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Snapshots struct {
		Items []snapshotItem `xml:"item"`
	} `xml:"snapshotSet"`
}

type snapshotItem struct {
	SnapshotID  string `xml:"snapshotId"`
	VolumeID    string `xml:"volumeId"`
	Status      string `xml:"status"`
	VolumeSize  int64  `xml:"volumeSize"`
	Description string `xml:"description,omitempty"`
}

type describeInstanceStatusXML struct {
	XMLName          struct{}             `xml:"DescribeInstanceStatusResponse"`
	RequestID        string               `xml:"requestId"`
	InstanceStatuses instanceStatusSetXML `xml:"instanceStatusSet"`
	NextToken        string               `xml:"nextToken,omitempty"`
}

type instanceStatusSetXML struct {
	Items []instanceStatusItem `xml:"item"`
}

type instanceStatusItem struct {
	InstanceID       string         `xml:"instanceId"`
	AvailabilityZone string         `xml:"availabilityZone"`
	State            stateXML       `xml:"instanceState"`
	SystemStatus     statusCheckXML `xml:"systemStatus"`
	InstanceStatus   statusCheckXML `xml:"instanceStatus"`
}

type statusCheckXML struct {
	Status  string            `xml:"status"`
	Details []statusDetailXML `xml:"details>item,omitempty"`
}

type statusDetailXML struct {
	Name   string `xml:"name"`
	Status string `xml:"status"`
}

type describeInstanceTypesXML struct {
	XMLName       struct{}           `xml:"DescribeInstanceTypesResponse"`
	RequestID     string             `xml:"requestId"`
	InstanceTypes instanceTypeSetXML `xml:"instanceTypeSet"`
	NextToken     string             `xml:"nextToken,omitempty"`
}

type instanceTypeSetXML struct {
	Items []instanceTypeItem `xml:"item"`
}

type instanceTypeItem struct {
	InstanceType                 string           `xml:"instanceType"`
	CurrentGeneration            bool             `xml:"currentGeneration"`
	FreeTierEligible             bool             `xml:"freeTierEligible"`
	SupportedUsageClasses        stringSetXML     `xml:"supportedUsageClasses"`
	SupportedRootDeviceTypes     stringSetXML     `xml:"supportedRootDeviceTypes"`
	SupportedVirtualizationTypes stringSetXML     `xml:"supportedVirtualizationTypes"`
	BareMetal                    bool             `xml:"bareMetal"`
	ProcessorInfo                processorInfoXML `xml:"processorInfo"`
	VCpuInfo                     vcpuInfoXML      `xml:"vCpuInfo"`
	MemoryInfo                   memoryInfoXML    `xml:"memoryInfo"`
}

type processorInfoXML struct {
	SupportedArchitectures stringSetXML `xml:"supportedArchitectures"`
}

type stringSetXML struct {
	Items []string `xml:"item"`
}

type vcpuInfoXML struct {
	DefaultVCpus          int `xml:"defaultVCpus"`
	DefaultCores          int `xml:"defaultCores"`
	DefaultThreadsPerCore int `xml:"defaultThreadsPerCore"`
}

type memoryInfoXML struct {
	SizeInMiB int64 `xml:"sizeInMiB"`
}

type describeTagsXML struct {
	XMLName   struct{}             `xml:"DescribeTagsResponse"`
	RequestID string               `xml:"requestId"`
	Tags      tagDescriptionSetXML `xml:"tagSet"`
	NextToken string               `xml:"nextToken,omitempty"`
}

type tagDescriptionSetXML struct {
	Items []tagDescriptionItem `xml:"item"`
}

type tagDescriptionItem struct {
	Key          string `xml:"key"`
	ResourceID   string `xml:"resourceId"`
	ResourceType string `xml:"resourceType"`
	Value        string `xml:"value"`
}

type describeVolumesModificationsXML struct {
	XMLName              struct{}                 `xml:"DescribeVolumesModificationsResponse"`
	RequestID            string                   `xml:"requestId"`
	VolumesModifications volumeModificationSetXML `xml:"volumeModificationSet"`
	NextToken            string                   `xml:"nextToken,omitempty"`
}

type volumeModificationSetXML struct {
	Items []volumeModificationItem `xml:"item"`
}

type volumeModificationItem struct {
	VolumeID string `xml:"volumeId"`
}

type describeAvailabilityZonesXML struct {
	XMLName           struct{}               `xml:"DescribeAvailabilityZonesResponse"`
	RequestID         string                 `xml:"requestId"`
	AvailabilityZones availabilityZoneSetXML `xml:"availabilityZoneInfo"`
}

type availabilityZoneSetXML struct {
	Items []availabilityZoneItem `xml:"item"`
}

type availabilityZoneItem struct {
	ZoneName           string `xml:"zoneName"`
	ZoneID             string `xml:"zoneId"`
	State              string `xml:"zoneState"`
	RegionName         string `xml:"regionName"`
	OptInStatus        string `xml:"optInStatus"`
	GroupName          string `xml:"groupName,omitempty"`
	GroupLongName      string `xml:"groupLongName,omitempty"`
	NetworkBorderGroup string `xml:"networkBorderGroup,omitempty"`
	ZoneType           string `xml:"zoneType,omitempty"`
}

type describeRegionsXML struct {
	XMLName   struct{}     `xml:"DescribeRegionsResponse"`
	RequestID string       `xml:"requestId"`
	Regions   regionSetXML `xml:"regionInfo"`
}

type regionSetXML struct {
	Items []regionItem `xml:"item"`
}

type regionItem struct {
	RegionName  string `xml:"regionName"`
	Endpoint    string `xml:"regionEndpoint"`
	OptInStatus string `xml:"optInStatus"`
}

type describeRouteTablesXML struct {
	XMLName     struct{}         `xml:"DescribeRouteTablesResponse"`
	RequestID   string           `xml:"requestId"`
	RouteTables routeTableSetXML `xml:"routeTableSet"`
	NextToken   string           `xml:"nextToken,omitempty"`
}

type routeTableSetXML struct {
	Items []routeTableItem `xml:"item"`
}

// routeTableItem is unreachable while VWS has no route tables. The type keeps
// the empty response's element name stable for EC2 clients.
type routeTableItem struct{}

type errorXML struct {
	XMLName   struct{} `xml:"Response"`
	Code      string   `xml:"Errors>Error>Code"`
	Message   string   `xml:"Errors>Error>Message"`
	RequestID string   `xml:"RequestID"`
}

func instanceItems(items []resource.Instance) instanceSet {
	var out instanceSet
	for _, inst := range items {
		out.Items = append(out.Items, instanceItem{
			InstanceID:   inst.ID.String(),
			ImageID:      inst.ImageID.String(),
			InstanceType: inst.InstanceType,
			KeyName:      inst.KeyName,
			SubnetID:     inst.SubnetID.String(),
			Zone:         inst.Zone,
			PrivateIP:    inst.PrivateIP,
			VpcID:        inst.VpcID.String(),
			LaunchTime:   launchTimeXML(inst.LaunchTime),
			PublicIP:     inst.PublicIP,
			NICs:         nicSetOf(inst),
			State:        stateXMLOf(inst.State),
			Reason:       stateReasonOf(inst.StateReason),
			Tags:         tagSetOf(inst.Tags),
			RootDevice:   inst.RootDeviceName,
			RootType:     rootTypeOf(inst),
			Blocks:       blockSetOf(inst),
		})
	}
	return out
}

func stateXMLOf(s resource.InstanceState) stateXML {
	return stateXML{Code: s.EC2Code(), Name: s.String()}
}

func stateReasonOf(r resource.StateReason) *stateReasonXML {
	if r.Code == "" && r.Message == "" {
		return nil
	}
	return &stateReasonXML{Code: r.Code, Message: r.Message}
}

func subnetXML(s resource.Subnet) subnetItem {
	return subnetItem{SubnetID: s.ID.String(), VpcID: s.VpcID.String(), Cidr: s.Cidr, State: s.State.String(), Zone: s.Zone, MapIP: s.MapPublicIPOnLaunch, Tags: tagSetOf(s.Tags)}
}

func vpcXML(v resource.Vpc) vpcItem {
	return vpcItem{VpcID: v.ID.String(), State: v.State, Cidr: v.Cidr, OwnerID: v.OwnerID.String(), Tags: tagSetOf(v.Tags)}
}

func volumeCreatedXML(requestID string, v resource.Volume) createVolumeXML {
	return createVolumeXML{
		RequestID: requestID, VolumeID: v.ID.String(), Size: v.SizeGiB,
		Zone: v.Zone, Status: string(v.State), Type: string(v.Type), Created: awsTime(v.CreateTime),
		Snapshot: snapshotOf(v), Iops: v.ReportedIops(), Throughput: v.Throughput,
	}
}

func snapshotOf(v resource.Volume) string {
	if v.SnapshotID.IsZero() {
		return ""
	}
	return v.SnapshotID.String()
}

func volumeXML(v resource.Volume) volumeItem {
	item := volumeItem{
		VolumeID: v.ID.String(), Size: v.SizeGiB, Zone: v.Zone, Status: string(v.State), Type: string(v.Type),
		Snapshot: snapshotOf(v), Created: awsTime(v.CreateTime),
		Iops: v.ReportedIops(), Throughput: v.Throughput,
	}
	if !v.InstanceID.IsZero() {
		// The backend reports attached only once the disk is on the machine;
		// an unset status is never shown as attached (#448).
		status := v.AttachState
		if status == "" {
			status = resource.AttachmentAttaching
		}
		item.Attachments.Items = []attachmentItem{{
			VolumeID: v.ID.String(), InstanceID: v.InstanceID.String(), Device: v.Device, Status: string(status),
			AttachTime:          awsTime(attachTimeOr(v.AttachTime, v.CreateTime)),
			DeleteOnTermination: v.DeleteOnTermination,
		}}
	}
	return item
}

func keyXML(key resource.KeyPair) keyItem {
	return keyItem{KeyPairID: key.ID.String(), KeyName: key.Name, Fingerprint: key.Fingerprint, KeyType: string(key.Type)}
}

func groupXML(group resource.SecurityGroup) groupItem {
	item := groupItem{GroupID: group.ID.String(), GroupName: group.Name, VpcID: group.VpcID.String()}
	for _, rule := range group.Rules {
		item.IPPermissions = append(item.IPPermissions, permissionItem{
			Protocol: rule.Protocol, FromPort: rule.FromPort, ToPort: rule.ToPort,
			IPRanges: []cidrItem{{CidrIP: rule.Cidr}},
		})
	}
	return item
}

func addressXML(addr resource.Address) addressItem {
	item := addressItem{
		PublicIP: addr.PublicIP, Domain: addr.Domain, AllocationID: addr.ID.String(), InstanceID: addr.InstanceID.String(),
	}
	if !addr.InstanceID.IsZero() {
		item.AssociationID = resource.AssociationID(addr.ID)
	}
	return item
}

func snapshotXML(snap resource.Snapshot) snapshotItem {
	return snapshotItem{
		SnapshotID: snap.ID.String(), VolumeID: snap.VolumeID.String(), Status: snap.State,
		VolumeSize: snap.VolumeSize, Description: snap.Description,
	}
}

func snapshotCreatedXML(requestID string, snap resource.Snapshot) createSnapshotXML {
	item := snapshotXML(snap)
	return createSnapshotXML{
		RequestID: requestID, SnapshotID: item.SnapshotID, VolumeID: item.VolumeID,
		Status: item.Status, VolumeSize: item.VolumeSize, Description: item.Description,
	}
}

func imageXML(img resource.Image) imageItem {
	return imageItem{
		ImageID: img.ID.String(), Name: img.Name, State: img.State, OwnerID: img.OwnerID.String(),
		Public: img.Public, Architecture: "x86_64", ImageType: "machine", RootDeviceType: "ebs",
		VirtualizationType: "hvm",
	}
}

// awsTime renders t as EC2 does (ISO 8601, UTC, milliseconds); zero is omitted.
// attachTimeOr is the attachment's attachTime: the time the backend recorded
// when the attachment initiated, or standIn when it records none. The gRPC
// backend records none: vws-proto has no attach timestamp (vws-proto#83),
// so a data volume shows its creation time and a block device its instance's
// launch time, the earliest the attachment can have initiated.
func attachTimeOr(recorded, standIn time.Time) time.Time {
	if !recorded.IsZero() {
		return recorded
	}
	return standIn
}

func awsTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// launchTimeXML formats a launch time as EC2 does, or empty when unknown.
func launchTimeXML(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// nicSetOf is the instance's network interface with its elastic IP, if any.
func nicSetOf(inst resource.Instance) *nicSet {
	nic := nicItem{
		SubnetID: inst.SubnetID.String(), VpcID: inst.VpcID.String(),
		OwnerID: inst.OwnerID.String(), PrivateIP: inst.PrivateIP,
	}
	if inst.PublicIP != "" {
		nic.Association = &nicAssociation{
			PublicIP: inst.PublicIP, IPOwnerID: inst.OwnerID.String(),
			AllocationID:  inst.PublicIPAllocationID.String(),
			AssociationID: resource.AssociationID(inst.PublicIPAllocationID),
		}
	}
	return &nicSet{Items: []nicItem{nic}}
}

func rootTypeOf(inst resource.Instance) string {
	if inst.RootDeviceName == "" {
		return ""
	}
	return "ebs"
}
