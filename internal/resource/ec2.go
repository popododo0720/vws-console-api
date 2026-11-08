package resource

import (
	"fmt"
	"log/slog"
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
	// AttachState is the attachment status while InstanceID is set: attaching
	// from AttachVolume until the backend reports the volume on the instance,
	// then attached. It is empty while detached.
	AttachState AttachmentStatus `json:"attachState,omitempty"`
	// DeleteOnTermination is set on an attached volume that is deleted when
	// its instance terminates. A root volume has it unless its launch kept it.
	DeleteOnTermination bool `json:"deleteOnTermination,omitempty"`
	// Iops and Throughput (MiB/s) are the provisioned performance of gp3,
	// io1 and io2. They are zero for every other type. ReportedIops is what
	// EC2 returns.
	Iops       int64 `json:"iops,omitempty"`
	Throughput int64 `json:"throughput,omitempty"`
}

// Owner returns the account that owns the volume.
func (v Volume) Owner() AccountID { return v.OwnerID }

// Identity returns the volume id.
func (v Volume) Identity() string { return v.ID.String() }

// VolumeType is the EC2 volume type name.
type VolumeType string

// The EBS volume types (EC2 VolumeType). CreateVolumeRequest.Normalize
// accepts all seven with the per-type rules of CheckVolumeShape.
const (
	VolumeStandard VolumeType = "standard"
	VolumeGP2      VolumeType = "gp2"
	VolumeGP3      VolumeType = "gp3"
	VolumeIO1      VolumeType = "io1"
	VolumeIO2      VolumeType = "io2"
	VolumeST1      VolumeType = "st1"
	VolumeSC1      VolumeType = "sc1"
)

// Valid reports whether t is one of the seven EBS volume types.
func (t VolumeType) Valid() bool {
	switch t {
	case VolumeStandard, VolumeGP2, VolumeGP3, VolumeIO1, VolumeIO2, VolumeST1, VolumeSC1:
		return true
	}
	return false
}

// CreateVolumeRequest allocates a volume. Iops and Throughput (MiB/s) are
// EC2's provisioned performance; zero means left out.
type CreateVolumeRequest struct {
	SizeGiB    int64      `json:"size"`
	Zone       string     `json:"availabilityZone"`
	Type       VolumeType `json:"volumeType,omitempty"`
	SnapshotID SnapshotID `json:"snapshotId,omitzero"`
	Iops       int64      `json:"iops,omitempty"`
	Throughput int64      `json:"throughput,omitempty"`
}

// Action returns CreateVolume.
func (CreateVolumeRequest) Action() Action { return ActionCreateVolume }

// Normalize checks the type, size, zone, Iops and Throughput. The type
// defaults to gp2, and gp3 Iops and Throughput to 3000 and 125. A volume
// restored from a snapshot may leave the size 0, which is the snapshot size;
// WithSize checks it once the backend knows it.
func (r CreateVolumeRequest) Normalize() (CreateVolumeRequest, error) {
	if r.Type == "" {
		r.Type = VolumeGP2
	}
	if !r.Type.Valid() {
		return CreateVolumeRequest{}, Invalid("volumeType", "unsupported")
	}
	if r.Iops < 0 {
		return CreateVolumeRequest{}, Invalid("iops", fmt.Sprintf("Value (%d) for parameter iops is invalid.", r.Iops))
	}
	if r.Throughput < 0 {
		return CreateVolumeRequest{}, Invalid("throughput",
			fmt.Sprintf("Value (%d) for parameter throughput is invalid.", r.Throughput))
	}
	if err := checkVolumePerformance(r.Type, r.Iops, r.Throughput); err != nil {
		return CreateVolumeRequest{}, err
	}
	r.Iops, r.Throughput = withDefaultPerformance(r.Type, r.Iops, r.Throughput)
	if r.SizeGiB < 0 || (r.SizeGiB == 0 && r.SnapshotID.IsZero()) {
		return CreateVolumeRequest{}, Invalid("size", fmt.Sprintf("Value (%d) for parameter size is invalid.", r.SizeGiB))
	}
	if r.SizeGiB != 0 {
		if err := CheckVolumeShape(r.Type, r.SizeGiB, r.Iops, r.Throughput); err != nil {
			return CreateVolumeRequest{}, err
		}
	}
	if r.Zone == "" {
		r.Zone = ZoneName
	}
	if r.Zone != ZoneName {
		return CreateVolumeRequest{}, Invalid("availabilityZone", "unsupported")
	}
	return r, nil
}

// WithSize sets the size of a volume restored from a snapshot with no size,
// and checks it against the type's rules.
func (r CreateVolumeRequest) WithSize(sizeGiB int64) (CreateVolumeRequest, error) {
	if err := CheckVolumeShape(r.Type, sizeGiB, r.Iops, r.Throughput); err != nil {
		return CreateVolumeRequest{}, err
	}
	r.SizeGiB = sizeGiB
	return r, nil
}

// AttachmentStatus is the EC2 attachment status (VolumeAttachment.status).
// It is not a volume state: a volume that is attaching is already in-use.
type AttachmentStatus string

// Attachment statuses this process returns, as EC2 VolumeAttachment.State.
// An attach accept is attaching, as on EC2, and a detach accept is
// detaching. Busy is a hot-plug or unplug the node is retrying.
const (
	AttachmentAttaching AttachmentStatus = "attaching"
	AttachmentAttached  AttachmentStatus = "attached"
	AttachmentDetaching AttachmentStatus = "detaching"
	AttachmentBusy      AttachmentStatus = "busy"
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
// InstanceId or Device does not name that bind. EC2 answers this with
// InvalidAttachment.NotFound and a sentence about the volume (#212).
func AttachmentNotFound(id VolumeID) *Error {
	return &Error{
		Code: CodeNotFound, Kind: KindVolume, ID: id.String(),
		Field: "attachment", Message: "The volume '" + id.String() + "' is not attached to the instance.",
	}
}

// IsAttachmentNotFound reports whether e came from AttachmentNotFound.
func IsAttachmentNotFound(e *Error) bool {
	return e != nil && e.Code == CodeNotFound && e.Kind == KindVolume && e.Field == "attachment"
}

// VolumeNotAvailable reports an AttachVolume for a volume that is not
// available. EC2 answers IncorrectState with this sentence (#212).
func VolumeNotAvailable(id VolumeID) *Error {
	return Conflict(KindVolume, id.String(), id.String()+" is not 'available'.")
}

// VolumeNotInUse reports a DetachVolume for a volume with no attachment.
// EC2 answers IncorrectState with this sentence (#212).
func VolumeNotInUse(id VolumeID) *Error {
	return Conflict(KindVolume, id.String(), "Volume '"+id.String()+"' is in the 'available' state.")
}

// DetachTokenExpiredMessage is the VWS answer to a DetachVolume retry whose
// client token compute no longer remembers while its detach record still
// lingers, and whose volume is attached again or elsewhere since. EC2
// DetachVolume takes no ClientToken, so AWS has no text for this (#305).
const DetachTokenExpiredMessage = "The client token for this DetachVolume expired; retry without it."

// DetachTokenExpired reports such a retry as IncorrectState. It never
// detaches again: once the record is pruned, the same token is a new detach.
func DetachTokenExpired(id VolumeID) *Error {
	return Conflict(KindVolume, id.String(), DetachTokenExpiredMessage)
}

// VolumeRootDevice reports a DetachVolume for an attached boot volume.
// EC2 answers IncorrectState with this sentence (#212).
func VolumeRootDevice(id VolumeID) *Error {
	return Conflict(KindVolume, id.String(), "Volume '"+id.String()+"' is in use as the root device.")
}

// VolumeAttached reports a DeleteVolume for a volume an instance still uses.
// EC2 answers VolumeInUse ("The specified EBS volume is attached to an
// instance", EC2 API Reference, Error codes) (#337).
func VolumeAttached(id VolumeID) *Error {
	return &Error{
		Code: CodeConflict, Kind: KindVolume, ID: id.String(),
		Field: "attachment", Message: "Volume " + id.String() + " is currently attached.",
	}
}

// IsVolumeAttached reports whether e came from VolumeAttached.
func IsVolumeAttached(e *Error) bool {
	return e != nil && e.Code == CodeConflict && e.Kind == KindVolume && e.Field == "attachment"
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
	if !ValidDeviceName(r.Device) {
		return AttachVolumeRequest{}, Invalid("device",
			"Value ("+r.Device+") for parameter device is invalid. "+r.Device+" is not a valid EBS device name.")
	}
	return r, nil
}

// ValidDeviceName reports whether name is one of the device names the EC2
// User Guide lists as available for an EBS volume ("Device names for volumes
// on Amazon EC2 instances"), on any instance: /dev/sd[a-z] and /dev/hd[a-z]
// with an optional partition 1 to 15, /dev/xvd[a-z], /dev/xvd[a-c][a-z] and
// /dev/xvdd[a-x], and the same xvd names without /dev/. The longest is 10
// bytes, so every name fits a detach record (#400).
func ValidDeviceName(name string) bool {
	rest, dev := strings.CutPrefix(name, "/dev/")
	if xvd, ok := strings.CutPrefix(rest, "xvd"); ok {
		return xvdSuffix(xvd)
	}
	if !dev || len(rest) < 3 || (rest[:2] != "sd" && rest[:2] != "hd") || !lower(rest[2], 'z') {
		return false
	}
	switch part := rest[3:]; len(part) {
	case 0:
		return true
	case 1:
		return part[0] >= '1' && part[0] <= '9'
	case 2:
		return part[0] == '1' && part[1] >= '0' && part[1] <= '5'
	default:
		return false
	}
}

func xvdSuffix(s string) bool {
	switch len(s) {
	case 1:
		return lower(s[0], 'z')
	case 2:
		return (lower(s[0], 'c') && lower(s[1], 'z')) || (s[0] == 'd' && lower(s[1], 'x'))
	default:
		return false
	}
}

// lower reports whether c is a lowercase letter from a to last.
func lower(c, last byte) bool { return c >= 'a' && c <= last }

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

// ModifyVolumeRequest changes a volume's size, type and provisioned
// performance in one request, as EC2 ModifyVolume. A zero field keeps the
// stored value; Volume.Modify gives the defaults of a type change.
type ModifyVolumeRequest struct {
	ID         VolumeID   `json:"volumeId"`
	SizeGiB    int64      `json:"size,omitempty"`
	Type       VolumeType `json:"volumeType,omitempty"`
	Iops       int64      `json:"iops,omitempty"`
	Throughput int64      `json:"throughput,omitempty"`
}

// Action returns ModifyVolume.
func (ModifyVolumeRequest) Action() Action { return ActionModifyVolume }

// Normalize checks the id, the type and that something is asked for. The
// ranges depend on the volume's current type and size, so the backend checks
// them with Volume.Modify once it has read the volume.
func (r ModifyVolumeRequest) Normalize() (ModifyVolumeRequest, error) {
	if r.ID.IsZero() {
		return ModifyVolumeRequest{}, Invalid("volumeId", "required")
	}
	for _, f := range []struct {
		name string
		v    int64
	}{{"size", r.SizeGiB}, {"iops", r.Iops}, {"throughput", r.Throughput}} {
		if f.v < 0 {
			return ModifyVolumeRequest{}, Invalid(f.name, fmt.Sprintf("Value (%d) for parameter %s is invalid.", f.v, f.name))
		}
	}
	if r.Type != "" && !r.Type.Valid() {
		return ModifyVolumeRequest{}, Invalid("volumeType", "unsupported")
	}
	if r.SizeGiB == 0 && r.Type == "" && r.Iops == 0 && r.Throughput == 0 {
		return ModifyVolumeRequest{}, MissingParameter("size",
			"The request must contain at least one of the parameters size, volumeType, iops or throughput.")
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
	// Etag is the compare-and-swap token the network service returns with the
	// group. It is not part of the console or EC2 shape.
	Etag string `json:"-"`
	// Labels holds the network service's labels. The client keeps the action
	// and request id there so a retry and a polled operation name the action.
	Labels map[string]string `json:"-"`
	Rules  []IngressRule     `json:"ipPermissions,omitempty"`
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

// IPPermission is one AWS IpPermissions entry. IngressRules flattens it. A nil
// port was not sent, which an ICMP permission may not do.
type IPPermission struct {
	Protocol         string            `json:"ipProtocol"`
	FromPort         *int              `json:"fromPort"`
	ToPort           *int              `json:"toPort"`
	IPRanges         []IPRange         `json:"ipRanges,omitempty"`
	IPv6Ranges       []IPv6Range       `json:"ipv6Ranges,omitempty"`
	UserIDGroupPairs []UserIDGroupPair `json:"userIdGroupPairs,omitempty"`
	PrefixListIDs    []PrefixListID    `json:"prefixListIds,omitempty"`
}

// IPRange is one IPv4 source of an IPPermission.
type IPRange struct {
	CidrIP      string `json:"cidrIp"`
	Description string `json:"description,omitempty"`
}

// IPv6Range is one IPv6 source of an IPPermission. VWS refuses it.
type IPv6Range struct {
	CidrIPv6    string `json:"cidrIpv6"`
	Description string `json:"description,omitempty"`
}

// UserIDGroupPair is one security group source of an IPPermission. VWS
// refuses it.
type UserIDGroupPair struct {
	Description            string `json:"description,omitempty"`
	GroupID                string `json:"groupId,omitempty"`
	GroupName              string `json:"groupName,omitempty"`
	PeeringStatus          string `json:"peeringStatus,omitempty"`
	UserID                 string `json:"userId,omitempty"`
	VpcID                  string `json:"vpcId,omitempty"`
	VpcPeeringConnectionID string `json:"vpcPeeringConnectionId,omitempty"`
}

// PrefixListID is one prefix list source of an IPPermission. VWS refuses it.
type PrefixListID struct {
	Description  string `json:"description,omitempty"`
	PrefixListID string `json:"prefixListId"`
}

// IngressRules flattens permissions into one rule per IPv4 range, in request
// order. A source kind or a range description VWS cannot store is refused,
// so no part of a permission is dropped.
func IngressRules(perms []IPPermission) ([]IngressRule, error) {
	var rules []IngressRule
	for _, p := range perms {
		switch {
		case len(p.IPv6Ranges) > 0:
			return nil, Unsupported("ipv6Ranges", "IPv6 ranges in security group rules are not supported.")
		case len(p.UserIDGroupPairs) > 0:
			return nil, Unsupported(
				"userIdGroupPairs",
				"Security group sources in security group rules are not supported.",
			)
		case len(p.PrefixListIDs) > 0:
			return nil, Unsupported("prefixListIds", "Prefix lists in security group rules are not supported.")
		case len(p.IPRanges) == 0:
			return nil, Invalid("ipRanges", "Each permission needs at least one IPv4 range.")
		}
		from, to, err := permissionPorts(p)
		if err != nil {
			return nil, err
		}
		for _, r := range p.IPRanges {
			if r.Description != "" {
				return nil, Unsupported("description", "Descriptions on security group rules are not supported.")
			}
			rules = append(
				rules,
				IngressRule{Protocol: p.Protocol, FromPort: from, ToPort: to, Cidr: r.CidrIP},
			)
		}
	}
	return rules, nil
}

// permissionPorts returns the permission's ports, 0 for one not sent. EC2
// requires a port range for icmp, so an ICMP permission without both its type
// and its code is refused. Reading the omission as 0/0 would store echo reply,
// and reading it as -1/-1 would allow every ICMP message.
func permissionPorts(p IPPermission) (int, int, error) {
	if protocol, err := canonicalProtocol(p.Protocol); err == nil && protocol == "icmp" {
		if p.FromPort == nil || p.ToPort == nil {
			return 0, 0, MissingParameter("fromPort",
				"An icmp permission must contain FromPort, the ICMP type, and ToPort, the ICMP code.")
		}
	}
	var from, to int
	if p.FromPort != nil {
		from = *p.FromPort
	}
	if p.ToPort != nil {
		to = *p.ToPort
	}
	return from, to, nil
}

// MaxIngressRules is the default EC2 quota of inbound rules per security
// group. A group holds at most this many, so one request adds at most this
// many too.
const MaxIngressRules = 60

// The ICMP type and code bounds. -1 means every type or every code.
const (
	icmpAny = -1
	icmpMax = 255
)

// AuthorizeSecurityGroupIngressRequest adds inbound rules, all or none.
type AuthorizeSecurityGroupIngressRequest struct {
	ID    SecurityGroupID `json:"groupId"`
	Rules []IngressRule   `json:"rules"`
}

// Action returns AuthorizeSecurityGroupIngress.
func (AuthorizeSecurityGroupIngressRequest) Action() Action {
	return ActionAuthorizeSecurityGroupIngress
}

// Normalize checks the group and canonicalizes each rule. A rule named twice
// is a duplicate, as a rule the group already has would be.
func (r AuthorizeSecurityGroupIngressRequest) Normalize() (AuthorizeSecurityGroupIngressRequest, error) {
	if r.ID.IsZero() {
		return AuthorizeSecurityGroupIngressRequest{}, Invalid("groupId", "required")
	}
	if len(r.Rules) == 0 {
		return AuthorizeSecurityGroupIngressRequest{}, MissingParameter(
			"ipPermissions",
			"The request must contain the parameter ipPermissions.",
		)
	}
	if len(r.Rules) > MaxIngressRules {
		return AuthorizeSecurityGroupIngressRequest{}, RulesPerSecurityGroupLimitExceeded(r.ID.String())
	}
	rules := make([]IngressRule, 0, len(r.Rules))
	for _, rule := range r.Rules {
		canon, err := normalizeRule(rule)
		if err != nil {
			return AuthorizeSecurityGroupIngressRequest{}, err
		}
		if slices.Contains(rules, canon) {
			return AuthorizeSecurityGroupIngressRequest{}, DuplicatePermission(r.ID.String())
		}
		rules = append(rules, canon)
	}
	return AuthorizeSecurityGroupIngressRequest{ID: r.ID, Rules: rules}, nil
}

// RevokeSecurityGroupIngressRequest removes one inbound rule.
type RevokeSecurityGroupIngressRequest struct {
	ID   SecurityGroupID `json:"groupId"`
	Rule IngressRule     `json:"ipPermissions"`
}

// Action returns RevokeSecurityGroupIngress.
func (RevokeSecurityGroupIngressRequest) Action() Action {
	return ActionRevokeSecurityGroupIngress
}

// Normalize checks the group and the rule.
func (r RevokeSecurityGroupIngressRequest) Normalize() (RevokeSecurityGroupIngressRequest, error) {
	id, rule, err := normalizeIngressRule(r.ID, r.Rule)
	if err != nil {
		return RevokeSecurityGroupIngressRequest{}, err
	}
	return RevokeSecurityGroupIngressRequest{ID: id, Rule: rule}, nil
}

func normalizeIngressRule(id SecurityGroupID, rule IngressRule) (SecurityGroupID, IngressRule, error) {
	if id.IsZero() {
		return SecurityGroupID{}, IngressRule{}, Invalid("groupId", "required")
	}
	rule, err := normalizeRule(rule)
	if err != nil {
		return SecurityGroupID{}, IngressRule{}, err
	}
	return id, rule, nil
}

func normalizeRule(rule IngressRule) (IngressRule, error) {
	protocol, err := canonicalProtocol(rule.Protocol)
	if err != nil {
		return IngressRule{}, err
	}
	rule.Protocol = protocol
	cidr, err := normalizeCIDR(rule.Cidr)
	if err != nil {
		return IngressRule{}, err
	}
	rule.Cidr = cidr
	if protocol == "-1" {
		rule.FromPort = 0
		rule.ToPort = 0
		return rule, nil
	}
	if protocol == "icmp" {
		return rule, checkICMP(rule.FromPort, rule.ToPort)
	}
	if rule.FromPort < 0 || rule.ToPort > 65535 || rule.ToPort < 0 || rule.FromPort > rule.ToPort {
		return IngressRule{}, Invalid("fromPort", "malformed")
	}
	return rule, nil
}

// checkICMP checks an ICMP type and code as EC2 does. Each is 0 to 255 or -1
// for all, and all types takes all codes.
func checkICMP(typ, code int) error {
	switch {
	case typ < icmpAny || typ > icmpMax:
		return Invalid("fromPort", fmt.Sprintf("Invalid value '%d' for ICMP type. It must be -1 or 0 to 255.", typ))
	case code < icmpAny || code > icmpMax:
		return Invalid("toPort", fmt.Sprintf("Invalid value '%d' for ICMP code. It must be -1 or 0 to 255.", code))
	case typ == icmpAny && code != icmpAny:
		return Invalid("toPort", "The ICMP code must be -1 when the ICMP type is -1.")
	default:
		return nil
	}
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

// Image is a machine image. Public marks one every project in its region can
// read, as an AWS public AMI. OwnerID is the account that owns it.
type Image struct {
	ID      ImageID   `json:"imageId"`
	OwnerID AccountID `json:"ownerId"`
	Name    string    `json:"name"`
	State   string    `json:"state"`
	Public  bool      `json:"public"`
	// SizeGiB is the smallest root volume the image boots from, and the
	// root size of a launch that names none. Zero means unknown.
	SizeGiB int64 `json:"size,omitempty"`
}

// Owner returns the account that owns the image.
func (i Image) Owner() AccountID { return i.OwnerID }

// Identity returns the image id.
func (i Image) Identity() string { return i.ID.String() }

// ImageQuery selects images. Owner limits the page to images that account
// owns; zero means any image the caller can read.
type ImageQuery struct {
	IDs   []ImageID   `json:"imageIds,omitempty"`
	Owner AccountID   `json:"ownerId,omitzero"`
	Page  PageRequest `json:"page,omitempty"`
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

// redactedKeyMaterial is what formatting and logging show in place of the
// private key. It is a fixed marker so a redacted value never varies.
const redactedKeyMaterial = "<redacted>"

// String returns the key pair without its private key.
func (k KeyPair) String() string {
	return fmt.Sprintf("KeyPair{ID: %s, OwnerID: %s, Name: %s, Fingerprint: %s, Type: %s, Material: %s}",
		k.ID, k.OwnerID, k.Name, k.Fingerprint, k.Type, redactedKeyMaterial)
}

// GoString returns the Go syntax of the key pair without its private key.
// fmt reaches for GoString on %#v, where String is not consulted.
func (k KeyPair) GoString() string {
	return fmt.Sprintf("resource.KeyPair{ID: %q, OwnerID: %q, Name: %q, Fingerprint: %q, Type: %q, Material: %q}",
		k.ID.String(), k.OwnerID.String(), k.Name, k.Fingerprint, k.Type, redactedKeyMaterial)
}

// LogValue returns the key pair as structured attributes without its private
// key. The keys use snake case, like the kernel audit records.
func (k KeyPair) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", k.ID.String()),
		slog.String("name", k.Name),
		slog.String("fingerprint", k.Fingerprint),
		slog.String("type", string(k.Type)),
		slog.String("material", redactedKeyMaterial),
	)
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
		ID: id, OwnerID: owner, Name: "vws-1", State: "available", SizeGiB: RootVolumeSizeGiB,
	}}
}

// CanLaunchImage reports whether KnownImages for owner names id in RegionName.
func CanLaunchImage(owner AccountID, id ImageID) bool {
	for _, img := range KnownImages(owner) {
		if img.ID == id && img.Name == RegionName {
			return true
		}
	}
	return false
}

// ImageNotFound reports an image id this process cannot launch in RegionName.
// EC2 answers this pair with 400 InvalidAMIID.NotFound.
func ImageNotFound(id ImageID) *Error {
	return &Error{
		Code:    CodeNotFound,
		Kind:    KindImage,
		Message: imageNotFoundMessage(id.String()),
	}
}

// imageNotFoundMessage is the text EC2 sends with InvalidAMIID.NotFound.
func imageNotFoundMessage(id string) string {
	return "The image id '[" + id + "]' does not exist"
}
