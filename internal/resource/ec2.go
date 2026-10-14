package resource

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Vpc is a regional IPv4 network.
type Vpc struct {
	ID      VpcID     `json:"vpcId"`
	OwnerID AccountID `json:"ownerId"`
	Cidr    string    `json:"cidrBlock"`
	State   string    `json:"state"`
	// IsDefault is always false: VWS has no default VPC.
	IsDefault bool              `json:"isDefault"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Owner returns the account that owns the VPC.
func (v Vpc) Owner() AccountID { return v.OwnerID }

// Identity returns the VPC id.
func (v Vpc) Identity() string { return v.ID.String() }

// CreateVpcRequest allocates a VPC.
type CreateVpcRequest struct {
	Cidr string            `json:"cidrBlock"`
	Tags map[string]string `json:"tags,omitempty"`
}

// Action returns CreateVpc.
func (CreateVpcRequest) Action() Action { return ActionCreateVpc }

// Normalize checks that cidr is an IPv4 network.
func (r CreateVpcRequest) Normalize() (CreateVpcRequest, error) {
	cidr, err := normalizeCIDR(r.Cidr)
	if err != nil {
		return CreateVpcRequest{}, err
	}
	r.Cidr = cidr
	if err := validTags(r.Tags); err != nil {
		return CreateVpcRequest{}, err
	}
	return r, nil
}

// DeleteVpcRequest deletes one VPC.
type DeleteVpcRequest struct {
	ID VpcID `json:"vpcId"`
}

// Action returns DeleteVpc.
func (DeleteVpcRequest) Action() Action { return ActionDeleteVpc }

// Normalize checks the id.
func (r DeleteVpcRequest) Normalize() (DeleteVpcRequest, error) {
	if r.ID.IsZero() {
		return DeleteVpcRequest{}, Invalid("vpcId", "required")
	}
	return r, nil
}

// VpcQuery selects VPCs.
type VpcQuery struct {
	IDs  []VpcID     `json:"vpcIds,omitempty"`
	Page PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q VpcQuery) Normalize() (VpcQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return VpcQuery{}, err
	}
	q.Page = page
	return q, nil
}

// VPC states. A create is pending until the next read, then available.
const (
	VpcPending   = "pending"
	VpcAvailable = "available"
	VpcDeleting  = "deleting"
)

// VolumeState is the life of a volume.
type VolumeState string

// The volume states.
const (
	VolumeCreating  VolumeState = "creating"
	VolumeAvailable VolumeState = "available"
	VolumeInUse     VolumeState = "in-use"
	VolumeDeleting  VolumeState = "deleting"
)

// Volume is a block device.
type Volume struct {
	ID         VolumeID    `json:"volumeId"`
	OwnerID    AccountID   `json:"ownerId"`
	SizeGiB    int64       `json:"size"`
	Zone       string      `json:"availabilityZone"`
	Type       VolumeType  `json:"volumeType"`
	State      VolumeState `json:"state"`
	InstanceID InstanceID  `json:"instanceId,omitempty"`
	Device     string      `json:"device,omitempty"`
	SnapshotID SnapshotID  `json:"snapshotId,omitzero"`
	CreateTime time.Time   `json:"createTime"`
	// DeleteOnTermination is set on a root volume, which goes with its instance.
	DeleteOnTermination bool `json:"deleteOnTermination,omitempty"`
}

// Owner returns the account that owns the volume.
func (v Volume) Owner() AccountID { return v.OwnerID }

// Identity returns the volume id.
func (v Volume) Identity() string { return v.ID.String() }

// VolumeType is the EC2 volume type name.
type VolumeType string

// Volume types CreateVolume accepts.
const (
	VolumeStandard VolumeType = "standard"
	VolumeGP2      VolumeType = "gp2"
	VolumeGP3      VolumeType = "gp3"
)

// CreateVolumeRequest allocates a volume.
type CreateVolumeRequest struct {
	SizeGiB    int64      `json:"size"`
	Zone       string     `json:"availabilityZone"`
	Type       VolumeType `json:"volumeType,omitempty"`
	SnapshotID SnapshotID `json:"snapshotId,omitzero"`
}

// Action returns CreateVolume.
func (CreateVolumeRequest) Action() Action { return ActionCreateVolume }

// Normalize checks the size, zone, and type. The type defaults to gp2.
// A volume restored from a snapshot may leave the size 0, which is the
// snapshot size.
func (r CreateVolumeRequest) Normalize() (CreateVolumeRequest, error) {
	switch r.Type {
	case "":
		r.Type = VolumeGP2
	case VolumeStandard, VolumeGP2, VolumeGP3:
	default:
		return CreateVolumeRequest{}, Invalid("volumeType", "unsupported")
	}
	if (r.SizeGiB < 1 && (r.SizeGiB != 0 || r.SnapshotID.IsZero())) || r.SizeGiB > 16384 {
		return CreateVolumeRequest{}, Invalid("size", "must be from 1 to 16384")
	}
	if r.Zone == "" {
		r.Zone = ZoneName
	}
	if r.Zone != ZoneName {
		return CreateVolumeRequest{}, Invalid("availabilityZone", "unsupported")
	}
	return r, nil
}

// AttachVolumeRequest attaches a volume to an instance.
type AttachVolumeRequest struct {
	VolumeID   VolumeID   `json:"volumeId"`
	InstanceID InstanceID `json:"instanceId"`
	Device     string     `json:"device"`
}

// Action returns AttachVolume.
func (AttachVolumeRequest) Action() Action { return ActionAttachVolume }

// Normalize checks the ids and device name.
func (r AttachVolumeRequest) Normalize() (AttachVolumeRequest, error) {
	if r.VolumeID.IsZero() {
		return AttachVolumeRequest{}, Invalid("volumeId", "required")
	}
	if r.InstanceID.IsZero() {
		return AttachVolumeRequest{}, Invalid("instanceId", "required")
	}
	if r.Device == "" {
		return AttachVolumeRequest{}, Invalid("device", "required")
	}
	return r, nil
}

// DeleteVolumeRequest deletes one volume.
type DeleteVolumeRequest struct {
	ID VolumeID `json:"volumeId"`
}

// Action returns DeleteVolume.
func (DeleteVolumeRequest) Action() Action { return ActionDeleteVolume }

// Normalize checks the id.
func (r DeleteVolumeRequest) Normalize() (DeleteVolumeRequest, error) {
	if r.ID.IsZero() {
		return DeleteVolumeRequest{}, Invalid("volumeId", "required")
	}
	return r, nil
}

// ModifyVolumeRequest grows a volume. Only the size can change: the storage
// backend serves no type change and never shrinks a volume.
type ModifyVolumeRequest struct {
	ID      VolumeID `json:"volumeId"`
	SizeGiB int64    `json:"size"`
}

// Action returns ModifyVolume.
func (ModifyVolumeRequest) Action() Action { return ActionModifyVolume }

// Normalize checks the id and the target size.
func (r ModifyVolumeRequest) Normalize() (ModifyVolumeRequest, error) {
	if r.ID.IsZero() {
		return ModifyVolumeRequest{}, Invalid("volumeId", "required")
	}
	if r.SizeGiB < 1 || r.SizeGiB > 16384 {
		return ModifyVolumeRequest{}, Invalid("size", "must be from 1 to 16384")
	}
	return r, nil
}

// VolumeQuery selects volumes.
type VolumeQuery struct {
	IDs  []VolumeID  `json:"volumeIds,omitempty"`
	Page PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q VolumeQuery) Normalize() (VolumeQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return VolumeQuery{}, err
	}
	q.Page = page
	return q, nil
}

// SecurityGroup is a set of ingress rules.
type SecurityGroup struct {
	ID      SecurityGroupID `json:"groupId"`
	OwnerID AccountID       `json:"ownerId"`
	Name    string          `json:"groupName"`
	VpcID   VpcID           `json:"vpcId"`
	Rules   []IngressRule   `json:"ipPermissions,omitempty"`
}

// Owner returns the account that owns the group.
func (g SecurityGroup) Owner() AccountID { return g.OwnerID }

// Identity returns the group id.
func (g SecurityGroup) Identity() string { return g.ID.String() }

// IngressRule is one inbound permission.
type IngressRule struct {
	Protocol string `json:"ipProtocol"`
	FromPort int    `json:"fromPort"`
	ToPort   int    `json:"toPort"`
	Cidr     string `json:"cidrIp"`
}

// CreateSecurityGroupRequest allocates a group in a VPC.
type CreateSecurityGroupRequest struct {
	Name  string `json:"groupName"`
	VpcID VpcID  `json:"vpcId"`
}

// Action returns CreateSecurityGroup.
func (CreateSecurityGroupRequest) Action() Action { return ActionCreateSecurityGroup }

// Normalize checks the name and VPC.
func (r CreateSecurityGroupRequest) Normalize() (CreateSecurityGroupRequest, error) {
	if r.Name == "" || len(r.Name) > 255 {
		return CreateSecurityGroupRequest{}, Invalid("groupName", "malformed")
	}
	if r.VpcID.IsZero() {
		return CreateSecurityGroupRequest{}, Invalid("vpcId", "required")
	}
	return r, nil
}

// AuthorizeSecurityGroupIngressRequest adds one inbound rule.
type AuthorizeSecurityGroupIngressRequest struct {
	ID   SecurityGroupID `json:"groupId"`
	Rule IngressRule     `json:"ipPermissions"`
}

// Action returns AuthorizeSecurityGroupIngress.
func (AuthorizeSecurityGroupIngressRequest) Action() Action {
	return ActionAuthorizeSecurityGroupIngress
}

// Normalize checks the group and the rule.
func (r AuthorizeSecurityGroupIngressRequest) Normalize() (AuthorizeSecurityGroupIngressRequest, error) {
	if r.ID.IsZero() {
		return AuthorizeSecurityGroupIngressRequest{}, Invalid("groupId", "required")
	}
	protocol, err := canonicalProtocol(r.Rule.Protocol)
	if err != nil {
		return AuthorizeSecurityGroupIngressRequest{}, err
	}
	r.Rule.Protocol = protocol
	cidr, err := normalizeCIDR(r.Rule.Cidr)
	if err != nil {
		return AuthorizeSecurityGroupIngressRequest{}, err
	}
	r.Rule.Cidr = cidr
	if protocol == "-1" {
		r.Rule.FromPort = 0
		r.Rule.ToPort = 0
		return r, nil
	}
	if r.Rule.FromPort < 0 || r.Rule.ToPort > 65535 || r.Rule.ToPort < 0 || r.Rule.FromPort > r.Rule.ToPort {
		return AuthorizeSecurityGroupIngressRequest{}, Invalid("fromPort", "malformed")
	}
	return r, nil
}

// canonicalProtocol accepts the names and protocol numbers a query client sends.
// Anything else is rejected. Mapping it to tcp would open a different port.
func canonicalProtocol(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp", "6":
		return "tcp", nil
	case "udp", "17":
		return "udp", nil
	case "icmp", "1":
		return "icmp", nil
	case "-1", "all":
		return "-1", nil
	default:
		return "", Invalid("ipProtocol", "unsupported")
	}
}

// Image is a machine image the caller can launch.
type Image struct {
	ID      ImageID   `json:"imageId"`
	OwnerID AccountID `json:"ownerId"`
	Name    string    `json:"name"`
	State   string    `json:"state"`
}

// Owner returns the account that owns the image.
func (i Image) Owner() AccountID { return i.OwnerID }

// Identity returns the image id.
func (i Image) Identity() string { return i.ID.String() }

// ImageQuery selects images.
type ImageQuery struct {
	IDs  []ImageID   `json:"imageIds,omitempty"`
	Page PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q ImageQuery) Normalize() (ImageQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return ImageQuery{}, err
	}
	q.Page = page
	return q, nil
}

// KeyType is an EC2 key pair type.
type KeyType string

// The key types EC2 offers. CreateKeyPair defaults to RSA.
const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeEd25519 KeyType = "ed25519"
)

// KeyFormat is the private key format CreateKeyPair returns.
type KeyFormat string

// The formats EC2 offers. CreateKeyPair defaults to PEM.
const (
	KeyFormatPEM KeyFormat = "pem"
	KeyFormatPPK KeyFormat = "ppk"
)

// KeyPair is an SSH key. Material is set only on the create that minted it.
type KeyPair struct {
	ID          KeyPairID `json:"keyPairId"`
	OwnerID     AccountID `json:"ownerId"`
	Name        string    `json:"keyName"`
	Fingerprint string    `json:"keyFingerprint"`
	Material    string    `json:"keyMaterial,omitempty"`
	Type        KeyType   `json:"keyType,omitempty"`
}

// Owner returns the account that owns the key pair.
func (k KeyPair) Owner() AccountID { return k.OwnerID }

// Identity returns the key pair id.
func (k KeyPair) Identity() string { return k.ID.String() }

// CreateKeyPairRequest mints a key pair of Type, or imports PublicKey when it
// is set. An imported key has no private key to return.
type CreateKeyPairRequest struct {
	Name      string  `json:"keyName"`
	Type      KeyType `json:"keyType,omitempty"`
	PublicKey string  `json:"publicKeyMaterial,omitempty"`
	// Format is the private key format of a created key.
	Format KeyFormat `json:"keyFormat,omitempty"`
}

// Action returns CreateKeyPair.
func (CreateKeyPairRequest) Action() Action { return ActionCreateKeyPair }

// Normalize checks the name and the type. The backend parses PublicKey,
// and an import takes its type from the key.
func (r CreateKeyPairRequest) Normalize() (CreateKeyPairRequest, error) {
	if r.Name == "" || len(r.Name) > 255 {
		return CreateKeyPairRequest{}, Invalid("keyName", "malformed")
	}
	if r.PublicKey != "" {
		r.Type, r.Format = "", ""
		return r, nil
	}
	switch r.Format {
	case "":
		r.Format = KeyFormatPEM
	case KeyFormatPEM, KeyFormatPPK:
	default:
		return CreateKeyPairRequest{}, Invalid("keyFormat", "must be pem or ppk")
	}
	switch r.Type {
	case "":
		r.Type = KeyTypeRSA
	case KeyTypeRSA, KeyTypeEd25519:
	default:
		return CreateKeyPairRequest{}, Invalid("keyType", "must be rsa or ed25519")
	}
	return r, nil
}

// DeleteKeyPairRequest deletes one key pair by id or by name.
type DeleteKeyPairRequest struct {
	ID   KeyPairID `json:"keyPairId,omitzero"`
	Name string    `json:"keyName,omitempty"`
}

// Action returns DeleteKeyPair.
func (DeleteKeyPairRequest) Action() Action { return ActionDeleteKeyPair }

// Normalize requires an id or a name.
func (r DeleteKeyPairRequest) Normalize() (DeleteKeyPairRequest, error) {
	if r.ID.IsZero() && r.Name == "" {
		return DeleteKeyPairRequest{}, Invalid("keyName", "required")
	}
	return r, nil
}

// KeyPairQuery selects key pairs.
type KeyPairQuery struct {
	IDs   []KeyPairID `json:"keyPairIds,omitempty"`
	Names []string    `json:"keyNames,omitempty"`
	Page  PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q KeyPairQuery) Normalize() (KeyPairQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return KeyPairQuery{}, err
	}
	q.Page = page
	return q, nil
}

// StartInstancesRequest starts stopped instances.
type StartInstancesRequest struct {
	IDs []InstanceID `json:"instanceIds"`
}

// Action returns StartInstances.
func (StartInstancesRequest) Action() Action { return ActionStartInstances }

// Normalize checks that at least one id is present.
func (r StartInstancesRequest) Normalize() (StartInstancesRequest, error) {
	if err := instanceIDs(r.IDs); err != nil {
		return StartInstancesRequest{}, err
	}
	return r, nil
}

// TerminateInstancesRequest terminates instances.
type TerminateInstancesRequest struct {
	IDs []InstanceID `json:"instanceIds"`
}

// Action returns TerminateInstances.
func (TerminateInstancesRequest) Action() Action { return ActionTerminateInstances }

// Normalize checks that at least one id is present.
func (r TerminateInstancesRequest) Normalize() (TerminateInstancesRequest, error) {
	if err := instanceIDs(r.IDs); err != nil {
		return TerminateInstancesRequest{}, err
	}
	return r, nil
}

func instanceIDs(ids []InstanceID) error {
	if len(ids) < 1 || len(ids) > 20 {
		return Invalid("instanceIds", "must list from 1 to 20 ids")
	}
	seen := map[InstanceID]struct{}{}
	for _, id := range ids {
		if id.IsZero() {
			return Invalid("instanceIds", "malformed")
		}
		if _, ok := seen[id]; ok {
			return Invalid("instanceIds", "duplicate")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func normalizeCIDR(cidr string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ip == nil || ip.To4() == nil || ipNet == nil {
		return "", Invalid("cidrBlock", "must be an ipv4 network")
	}
	return ipNet.String(), nil
}

// knownImageID is the one machine image this process can launch.
const knownImageID = "ami-0123456789abcdef0"

// KnownImages is the machine image this process can launch. The owner is the
// caller, so a describe result passes the tenancy check. It is a function so
// the catalog is not package state.
func KnownImages(owner AccountID) []Image {
	id, err := Parse[ImageID](knownImageID)
	if err != nil {
		// The id is a constant. A parse failure is a programming error, and an
		// empty catalog would hide it as "no images" on every surface.
		panic(fmt.Sprintf("resource: known image id %q: %v", knownImageID, err))
	}
	return []Image{{
		ID: id, OwnerID: owner, Name: "vws-1", State: "available",
	}}
}
