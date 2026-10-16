package resource

import (
	"fmt"
	"net"
	"slices"
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
	// VolumeError is the EC2 status of a volume whose reconcile failed.
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Volume.html
	VolumeError VolumeState = "error"
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
	// AttachTime is when the volume was attached. It stays zero while detached.
	AttachTime time.Time `json:"attachTime,omitzero"`
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

// AttachmentStatus is the EC2 attachment status on a detach accept.
// It is not a volume state.
type AttachmentStatus string

// Attachment statuses this process returns. A detach accept is detaching.
const (
	AttachmentAttached  AttachmentStatus = "attached"
	AttachmentDetaching AttachmentStatus = "detaching"
)

// VolumeAttachment is the accept item for DetachVolume.
// Identity is the instance id because the operation targets that instance.
type VolumeAttachment struct {
	VolumeID   VolumeID         `json:"volumeId"`
	OwnerID    AccountID        `json:"ownerId"`
	InstanceID InstanceID       `json:"instanceId"`
	Device     string           `json:"device"`
	Status     AttachmentStatus `json:"status"`
	AttachTime time.Time        `json:"attachTime"`
}

// Owner returns the account that owns the attachment.
func (a VolumeAttachment) Owner() AccountID { return a.OwnerID }

// Identity returns the instance id. guardAccepted matches operation targets to it.
func (a VolumeAttachment) Identity() string { return a.InstanceID.String() }

// DetachVolumeRequest detaches one volume. Instance, device, and force are optional.
type DetachVolumeRequest struct {
	VolumeID   VolumeID   `json:"volumeId"`
	InstanceID InstanceID `json:"instanceId,omitzero"`
	Device     string     `json:"device,omitempty"`
	// Force is part of the fingerprint. Nothing applies it: there is no guest flush.
	Force bool `json:"force,omitempty"`
}

// Action returns DetachVolume.
func (DetachVolumeRequest) Action() Action { return ActionDetachVolume }

// Normalize requires a volume id. It does not look at Force.
func (r DetachVolumeRequest) Normalize() (DetachVolumeRequest, error) {
	if r.VolumeID.IsZero() {
		return DetachVolumeRequest{}, Invalid("volumeId", "required")
	}
	return r, nil
}

// AttachmentNotFound reports a DetachVolume whose volume is bound and whose
// InstanceId or Device does not name that bind.
func AttachmentNotFound(id VolumeID) *Error {
	return &Error{
		Code: CodeNotFound, Kind: KindVolume, ID: id.String(),
		Field: "attachment", Message: "attachment not found",
	}
}

// IsAttachmentNotFound reports whether e came from AttachmentNotFound.
func IsAttachmentNotFound(e *Error) bool {
	return e != nil && e.Code == CodeNotFound && e.Kind == KindVolume && e.Field == "attachment"
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

// IngressRule is one inbound permission stored on a group.
type IngressRule struct {
	Protocol string `json:"ipProtocol"`
	FromPort int    `json:"fromPort"`
	ToPort   int    `json:"toPort"`
	Cidr     string `json:"cidrIp"`
}

// IngressChange is one stored rule and the client paths that produced it.
// Path and Perm are omitted from JSON, so the idempotency fingerprint is the flat rule list.
type IngressChange struct {
	IngressRule
	Path string `json:"-"`
	Perm string `json:"-"`
}

func (c IngressChange) field(leaf string) string {
	base := c.Path
	if leaf != "cidrIp" {
		base = c.Perm
	}
	if base == "" {
		return leaf
	}
	return base + "." + leaf
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

// AuthorizeSecurityGroupIngressRequest adds flat IPv4 rules to one group.
// Rules is the canonical list Normalize produces. Its JSON is the idempotency fingerprint.
type AuthorizeSecurityGroupIngressRequest struct {
	ID    SecurityGroupID `json:"groupId"`
	Rules []IngressChange `json:"ipPermissions"`
}

// Action returns AuthorizeSecurityGroupIngress.
func (AuthorizeSecurityGroupIngressRequest) Action() Action {
	return ActionAuthorizeSecurityGroupIngress
}

// Normalize canonicalizes every rule and rejects an empty list or a repeated rule.
// The returned slice is sorted, so two bodies that name the same rules share a fingerprint.
func (r AuthorizeSecurityGroupIngressRequest) Normalize() (AuthorizeSecurityGroupIngressRequest, error) {
	if r.ID.IsZero() {
		return AuthorizeSecurityGroupIngressRequest{}, Invalid("groupId", "required")
	}
	if len(r.Rules) == 0 {
		return AuthorizeSecurityGroupIngressRequest{}, MalformedPermission("ipPermissions", "required")
	}
	out := make([]IngressChange, len(r.Rules))
	seen := make(map[IngressRule]struct{}, len(r.Rules))
	for i, rule := range r.Rules {
		protocol, err := canonicalProtocol(rule.Protocol)
		if err != nil {
			return AuthorizeSecurityGroupIngressRequest{}, MalformedPermission(rule.field("ipProtocol"), "unsupported")
		}
		cidr, err := normalizeCIDR(rule.Cidr)
		if err != nil {
			return AuthorizeSecurityGroupIngressRequest{}, MalformedPermission(rule.field("cidrIp"), "must be an ipv4 network")
		}
		rule.Protocol = protocol
		rule.Cidr = cidr
		if protocol == "-1" {
			rule.FromPort = 0
			rule.ToPort = 0
		} else if rule.FromPort < 0 || rule.ToPort > 65535 || rule.ToPort < 0 || rule.FromPort > rule.ToPort {
			return AuthorizeSecurityGroupIngressRequest{}, MalformedPermission(rule.field("fromPort"), "malformed")
		}
		if _, ok := seen[rule.IngressRule]; ok {
			return AuthorizeSecurityGroupIngressRequest{}, DuplicatePermission(r.ID.String(), rule.Path)
		}
		seen[rule.IngressRule] = struct{}{}
		out[i] = rule
	}
	slices.SortFunc(out, func(a, b IngressChange) int {
		if a.Protocol != b.Protocol {
			return strings.Compare(a.Protocol, b.Protocol)
		}
		if a.FromPort != b.FromPort {
			return a.FromPort - b.FromPort
		}
		if a.ToPort != b.ToPort {
			return a.ToPort - b.ToPort
		}
		return strings.Compare(a.Cidr, b.Cidr)
	})
	r.Rules = out
	return r, nil
}

// CheckIngressBatch reports a rule the group already has, or a repeat in this call.
func CheckIngressBatch(id string, existing []IngressRule, add []IngressChange) error {
	seen := make(map[IngressRule]struct{}, len(existing)+len(add))
	for _, rule := range existing {
		seen[rule] = struct{}{}
	}
	for _, rule := range add {
		if _, ok := seen[rule.IngressRule]; ok {
			return DuplicatePermission(id, rule.Path)
		}
		seen[rule.IngressRule] = struct{}{}
	}
	return nil
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
