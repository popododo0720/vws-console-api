package ec2query

import (
	"encoding/xml"
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
	Instances     instanceSet `xml:"instancesSet"`
}

type instanceSet struct {
	Items []instanceItem `xml:"item"`
}

type instanceItem struct {
	InstanceID   string   `xml:"instanceId"`
	ImageID      string   `xml:"imageId"`
	InstanceType string   `xml:"instanceType"`
	SubnetID     string   `xml:"subnetId"`
	Zone         string   `xml:"placement>availabilityZone"`
	PrivateIP    string   `xml:"privateIpAddress,omitempty"`
	State        stateXML `xml:"instanceState"`
}

type stateXML struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
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
	SubnetID string `xml:"subnetId"`
	VpcID    string `xml:"vpcId,omitempty"`
	Cidr     string `xml:"cidrBlock"`
	State    string `xml:"state"`
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
	VpcID     string `xml:"vpcId"`
	State     string `xml:"state"`
	Cidr      string `xml:"cidrBlock"`
	OwnerID   string `xml:"ownerId"`
	IsDefault bool   `xml:"isDefault"`
}

type deleteVpcXML struct {
	XMLName   struct{} `xml:"DeleteVpcResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

type createVolumeXML struct {
	XMLName   struct{} `xml:"CreateVolumeResponse"`
	RequestID string   `xml:"requestId"`
	VolumeID  string   `xml:"volumeId"`
	Size      int64    `xml:"size"`
	Zone      string   `xml:"availabilityZone"`
	Status    string   `xml:"status"`
	Type      string   `xml:"volumeType"`
	Created   string   `xml:"createTime,omitempty"`
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
	Created     string `xml:"createTime,omitempty"`
	Attachments struct {
		Items []attachmentItem `xml:"item"`
	} `xml:"attachmentSet,omitempty"`
}

type attachmentItem struct {
	VolumeID   string `xml:"volumeId"`
	InstanceID string `xml:"instanceId"`
	Device     string `xml:"device"`
	Status     string `xml:"status"`
}

type attachVolumeXML struct {
	XMLName    struct{} `xml:"AttachVolumeResponse"`
	RequestID  string   `xml:"requestId"`
	VolumeID   string   `xml:"volumeId"`
	InstanceID string   `xml:"instanceId"`
	Device     string   `xml:"device"`
	Status     string   `xml:"status"`
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

type describeAddressesXML struct {
	XMLName   struct{} `xml:"DescribeAddressesResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Addresses struct {
		Items []addressItem `xml:"item"`
	} `xml:"addressesSet"`
}

type addressItem struct {
	PublicIP     string `xml:"publicIp,omitempty"`
	Domain       string `xml:"domain,omitempty"`
	AllocationID string `xml:"allocationId"`
	InstanceID   string `xml:"instanceId,omitempty"`
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
			SubnetID:     inst.SubnetID.String(),
			Zone:         inst.Zone,
			PrivateIP:    inst.PrivateIP,
			State:        stateXMLOf(inst.State),
		})
	}
	return out
}

func stateXMLOf(s resource.InstanceState) stateXML {
	return stateXML{Code: s.EC2Code(), Name: s.String()}
}

func subnetXML(s resource.Subnet) subnetItem {
	return subnetItem{SubnetID: s.ID.String(), VpcID: s.VpcID.String(), Cidr: s.Cidr, State: s.State.String()}
}

func vpcXML(v resource.Vpc) vpcItem {
	return vpcItem{VpcID: v.ID.String(), State: v.State, Cidr: v.Cidr, OwnerID: v.OwnerID.String()}
}

func volumeCreatedXML(requestID string, v resource.Volume) createVolumeXML {
	return createVolumeXML{
		RequestID: requestID, VolumeID: v.ID.String(), Size: v.SizeGiB,
		Zone: v.Zone, Status: string(v.State), Type: string(v.Type), Created: awsTime(v.CreateTime),
	}
}

func volumeXML(v resource.Volume) volumeItem {
	item := volumeItem{
		VolumeID: v.ID.String(), Size: v.SizeGiB, Zone: v.Zone, Status: string(v.State), Type: string(v.Type),
		Created: awsTime(v.CreateTime),
	}
	if !v.InstanceID.IsZero() {
		item.Attachments.Items = []attachmentItem{{
			VolumeID: v.ID.String(), InstanceID: v.InstanceID.String(), Device: v.Device, Status: "attached",
		}}
	}
	return item
}

func keyXML(key resource.KeyPair) keyItem {
	return keyItem{KeyPairID: key.ID.String(), KeyName: key.Name, Fingerprint: key.Fingerprint}
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
	return addressItem{
		PublicIP: addr.PublicIP, Domain: addr.Domain, AllocationID: addr.ID.String(), InstanceID: addr.InstanceID.String(),
	}
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
		Architecture: "x86_64", ImageType: "machine", RootDeviceType: "ebs", VirtualizationType: "hvm",
	}
}

// awsTime renders t as EC2 does (ISO 8601, UTC, milliseconds); zero is omitted.
func awsTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
