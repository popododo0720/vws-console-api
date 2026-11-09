package resource

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// InstanceState is the life of an instance. The names are the EC2 state names.
type InstanceState int

// The instance states.
const (
	instanceStateNone InstanceState = iota
	InstancePending
	InstanceRunning
	InstanceStopping
	InstanceStopped
	InstanceShuttingDown
	InstanceTerminated
)

// String returns the wire name.
func (s InstanceState) String() string {
	switch s {
	case InstancePending:
		return "pending"
	case InstanceRunning:
		return "running"
	case InstanceStopping:
		return "stopping"
	case InstanceStopped:
		return "stopped"
	case InstanceShuttingDown:
		return "shutting-down"
	case InstanceTerminated:
		return "terminated"
	case instanceStateNone:
		return ""
	default:
		return ""
	}
}

// ParseInstanceState returns the state named s.
func ParseInstanceState(s string) (InstanceState, bool) {
	for st := InstanceState(1); st.String() != ""; st++ {
		if st.String() == s {
			return st, true
		}
	}
	return instanceStateNone, false
}

// MarshalText encodes the wire name.
func (s InstanceState) MarshalText() ([]byte, error) {
	if s.String() == "" {
		return nil, Invalid("state", "required")
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses the wire name.
func (s *InstanceState) UnmarshalText(b []byte) error {
	parsed, ok := ParseInstanceState(string(b))
	if !ok {
		return Invalid("state", "unknown")
	}
	*s = parsed
	return nil
}

// StateReason is the EC2 explanation of the latest state transition.
// An empty value means EC2 would omit stateReason.
type StateReason struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

const (
	// ServerInternalError is the EC2 state-reason code for an instance that
	// terminated during launch because of an internal error.
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StateReason.html
	ServerInternalError = "Server.InternalError"
	// ServerInternalErrorMessage is the message EC2 publishes with that code.
	ServerInternalErrorMessage = "Server.InternalError: " +
		"An internal error caused the instance to terminate during launch"
)

// EC2Code is the numeric code EC2 Query uses for s.
func (s InstanceState) EC2Code() int {
	switch s {
	case InstancePending:
		return 0
	case InstanceRunning:
		return 16
	case InstanceShuttingDown:
		return 32
	case InstanceTerminated:
		return 48
	case InstanceStopping:
		return 64
	case InstanceStopped:
		return 80
	case instanceStateNone:
		return -1
	default:
		return -1
	}
}

// Instance is a virtual machine.
type Instance struct {
	ID            InstanceID    `json:"instanceId"`
	ReservationID ReservationID `json:"reservationId"`
	OwnerID       AccountID     `json:"ownerId"`
	State         InstanceState `json:"state"`
	StateReason   StateReason   `json:"stateReason,omitzero"`
	ImageID       ImageID       `json:"imageId"`
	InstanceType  string        `json:"instanceType"`
	// SubnetID, VpcID and PrivateIP are those of the primary interface,
	// device index 0, as in EC2. SetInterfaces keeps them so.
	SubnetID   SubnetID  `json:"subnetId"`
	VpcID      VpcID     `json:"vpcId,omitzero"`
	Zone       string    `json:"availabilityZone"`
	LaunchTime time.Time `json:"launchTime,omitzero"`
	// PublicIP and PublicIPAllocationID come from the elastic IP associated
	// with the instance. Both are empty when there is none.
	PublicIP             string            `json:"publicIpAddress,omitempty"`
	PublicIPAllocationID AddressID         `json:"publicIpAllocationId,omitzero"`
	PrivateIP            string            `json:"privateIpAddress,omitempty"`
	Tags                 map[string]string `json:"tags,omitempty"`
	KeyName              string            `json:"keyName,omitempty"`
	// KeyPairID is the key pair the backend names. A backend that stores only
	// the id leaves KeyName for the read path to fill.
	KeyPairID KeyPairID `json:"-"`
	// UserData is served by DescribeInstanceAttribute, not by listings.
	UserData string `json:"-"`
	// RootDeviceName is RootDeviceName when the instance boots from a volume.
	RootDeviceName string        `json:"rootDeviceName,omitempty"`
	BlockDevices   []BlockDevice `json:"blockDeviceMappings,omitempty"`
	// DetachingDevices are volumes the spec no longer names that the node is
	// still letting go. EC2 lists them in blockDeviceMapping as detaching
	// until the detach completes. They hold no bind: nothing can detach,
	// rebind or boot from them.
	DetachingDevices []BlockDevice `json:"-"`
	// NetworkInterfaces are in device order. Each is on an overlay or a
	// direct subnet.
	NetworkInterfaces []NetworkInterface `json:"networkInterfaces,omitempty"`
}

// NetworkInterface is one interface of an instance.
type NetworkInterface struct {
	DeviceIndex int      `json:"deviceIndex"`
	SubnetID    SubnetID `json:"subnetId"`
	VpcID       VpcID    `json:"vpcId,omitzero"`
	PrivateIP   string   `json:"privateIpAddress,omitempty"`
}

// SetInterfaces stores nics in device order and copies the primary one's
// subnet, VPC and address to the instance.
func (i *Instance) SetInterfaces(nics []NetworkInterface) {
	sorted := slices.Clone(nics)
	slices.SortFunc(sorted, func(a, b NetworkInterface) int { return cmp.Compare(a.DeviceIndex, b.DeviceIndex) })
	i.NetworkInterfaces = sorted
	if len(sorted) > 0 && sorted[0].DeviceIndex == 0 {
		i.SubnetID, i.VpcID, i.PrivateIP = sorted[0].SubnetID, sorted[0].VpcID, sorted[0].PrivateIP
	}
}

// Interfaces returns the instance's interfaces, or the primary one alone
// when the instance lists none.
func (i Instance) Interfaces() []NetworkInterface {
	if len(i.NetworkInterfaces) > 0 {
		return i.NetworkInterfaces
	}
	return []NetworkInterface{{SubnetID: i.SubnetID, VpcID: i.VpcID, PrivateIP: i.PrivateIP}}
}

// RootDeviceName is the device EC2 reports for an instance's boot volume.
const RootDeviceName = "/dev/xvda"

// BlockDevice is one EBS volume attached to an instance.
type BlockDevice struct {
	Device              string   `json:"deviceName"`
	VolumeID            VolumeID `json:"volumeId"`
	DeleteOnTermination bool     `json:"deleteOnTermination"`
	// Status is the attachment status (EC2 EbsInstanceBlockDevice.Status).
	// It is attached only once the backend reports the disk on the machine.
	Status AttachmentStatus `json:"status"`
	// AttachTime is when the attachment initiated (EC2
	// EbsInstanceBlockDevice.AttachTime). It is zero when the backend does
	// not record one.
	AttachTime time.Time `json:"attachTime,omitzero"`
}

// Owner returns the account that owns the instance.
func (i Instance) Owner() AccountID { return i.OwnerID }

// Identity returns the instance id.
func (i Instance) Identity() string { return i.ID.String() }

// InstanceStateChange is the accept-time result of StopInstances.
type InstanceStateChange struct {
	ID       InstanceID    `json:"instanceId"`
	OwnerID  AccountID     `json:"ownerId"`
	Previous InstanceState `json:"previousState"`
	Current  InstanceState `json:"currentState"`
}

// Owner returns the account that owns the instance.
func (c InstanceStateChange) Owner() AccountID { return c.OwnerID }

// Identity returns the instance id.
func (c InstanceStateChange) Identity() string { return c.ID.String() }

// RunInstancesRequest launches one or more instances. It names either
// SubnetID, for one interface, or NetworkInterfaces.
type RunInstancesRequest struct {
	ImageID      ImageID           `json:"imageId"`
	InstanceType string            `json:"instanceType"`
	SubnetID     SubnetID          `json:"subnetId"`
	Count        int               `json:"count"`
	Tags         map[string]string `json:"tags,omitempty"`
	KeyName      string            `json:"keyName,omitempty"`
	// UserData is the decoded text handed to the guest on boot.
	UserData string `json:"userData,omitempty"`
	// RootVolumeType is the EBS type of the root volume, from the request's
	// block device mapping for the root device. Empty means the image
	// default; see RootType.
	RootVolumeType VolumeType `json:"rootVolumeType,omitempty"`
	// RootIops and RootThroughput are the root mapping's Ebs.Iops and
	// Ebs.Throughput (MiB/s). Zero means omitted; see RootPerformance.
	RootIops       int64 `json:"rootIops,omitempty"`
	RootThroughput int64 `json:"rootThroughput,omitempty"`
	// RootVolumeSize is the root mapping's Ebs.VolumeSize in GiB. Zero means
	// omitted; see RootSize.
	RootVolumeSize int64 `json:"rootVolumeSize,omitempty"`
	// RootVolumeKept is the root mapping's Ebs.DeleteOnTermination=false:
	// the root volume is detached and kept when the instance terminates.
	// False is the EC2 default, so the fingerprint of a request that omits
	// it does not change.
	RootVolumeKept bool `json:"rootVolumeKept,omitempty"`
	// ExtraVolumes are the mappings for devices other than the root, in the
	// order sent: each instance gets one new volume per entry. Empty marshals
	// to nothing, so the fingerprint of a request without one does not
	// change.
	ExtraVolumes []LaunchVolume `json:"extraVolumes,omitempty"`
	// NetworkInterfaces places each interface on a subnet by device index
	// (EC2 NetworkInterface.N). Any of them, the primary included, may be
	// on a direct subnet.
	NetworkInterfaces []NetworkInterfaceSpec `json:"networkInterfaces,omitempty"`
}

// MaxNetworkInterfaces is the most interfaces one instance takes, device
// indexes 0 to MaxNetworkInterfaces-1. vws-compute sets no limit; 8 is the
// EC2 limit of the smaller instance types.
const MaxNetworkInterfaces = 8

// NetworkInterfaceSpec is one interface of a launch. Device index 0 is the
// primary interface.
type NetworkInterfaceSpec struct {
	DeviceIndex int      `json:"deviceIndex"`
	SubnetID    SubnetID `json:"subnetId"`
}

// UnmarshalJSON requires deviceIndex, as EC2 does, so an omitted index is
// refused instead of read as the primary interface. The decoder is strict
// because a custom unmarshaler does not inherit the caller's.
func (s *NetworkInterfaceSpec) UnmarshalJSON(b []byte) error {
	var wire struct {
		DeviceIndex *int     `json:"deviceIndex"`
		SubnetID    SubnetID `json:"subnetId"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		var e *Error
		if errors.As(err, &e) {
			return e
		}
		return Invalid("body", "malformed json")
	}
	if wire.DeviceIndex == nil {
		return MissingParameter("deviceIndex", "When specifying network interfaces, you must include a device index.")
	}
	*s = NetworkInterfaceSpec{DeviceIndex: *wire.DeviceIndex, SubnetID: wire.SubnetID}
	return nil
}

// Interfaces is the launch's interfaces in device order: NetworkInterfaces,
// or SubnetID as device 0.
func (r RunInstancesRequest) Interfaces() []NetworkInterfaceSpec {
	if len(r.NetworkInterfaces) > 0 {
		return r.NetworkInterfaces
	}
	return []NetworkInterfaceSpec{{SubnetID: r.SubnetID}}
}

// LaunchVolume is one non-root block device mapping of RunInstances: a blank
// EBS volume each instance is launched with, attached at Device (#423 AC2).
type LaunchVolume struct {
	Device  string `json:"deviceName"`
	SizeGiB int64  `json:"size"`
	// Type is the mapping's Ebs.VolumeType. Empty means gp2; see VolumeType.
	Type       VolumeType `json:"volumeType,omitempty"`
	Iops       int64      `json:"iops,omitempty"`
	Throughput int64      `json:"throughput,omitempty"`
	// Kept is the mapping's Ebs.DeleteOnTermination=false. False is the EC2
	// default for a volume mapped at launch (User Guide, "Preserve data when
	// an instance is terminated"): it is deleted with its instance.
	Kept bool `json:"kept,omitempty"`
}

// VolumeType is the EBS type of the volume: the mapping's, or gp2, the
// CreateVolume default.
func (v LaunchVolume) VolumeType() VolumeType {
	if v.Type == "" {
		return VolumeGP2
	}
	return v.Type
}

// Performance is the Iops and Throughput (MiB/s) of the volume: the
// mapping's, and for an omitted one what EC2 fills in for its type.
func (v LaunchVolume) Performance() (iops, miBps int64) {
	return withDefaultPerformance(v.VolumeType(), v.Iops, v.Throughput)
}

// MaxLaunchVolumes is the EBS volumes RunInstances attaches to one instance,
// the root included: a Nitro instance shares 28 attachments between its
// volumes and network interfaces, and a VWS instance has one interface
// (User Guide, "Amazon EBS volume limits").
const MaxLaunchVolumes = 27

// RootVolumeSizeGiB is the smallest root volume RunInstances creates when
// the request names no size, and the size of the catalog image.
const RootVolumeSizeGiB = 8

// RootSize is the mapping's Ebs.VolumeSize in GiB, or RootVolumeSizeGiB when
// it is omitted. Normalize checks a size the request names; the backend
// resolves an omitted one against the image with RootSizeFor.
func (r RunInstancesRequest) RootSize() int64 {
	if r.RootVolumeSize == 0 {
		return RootVolumeSizeGiB
	}
	return r.RootVolumeSize
}

// RootSizeFor is the root volume size in GiB RunInstances gives a launch of
// img. An omitted size is the image's size when that is above
// RootVolumeSizeGiB, as EC2 defaults VolumeSize to the snapshot size. A size
// below the image is refused as EC2 refuses it, with InvalidBlockDeviceMapping
// (EbsBlockDevice VolumeSize: "equal to or larger than the snapshot size"),
// and the size is checked again with the CreateVolume per-type rules. An image
// of unknown size (zero) is left to storage.
func (r RunInstancesRequest) RootSizeFor(img Image) (int64, error) {
	size := r.RootSize()
	if r.RootVolumeSize == 0 && img.SizeGiB > size {
		size = img.SizeGiB
	}
	if size < img.SizeGiB {
		return 0, Invalid("blockDeviceMapping", fmt.Sprintf(
			"Volume of size %dGB is smaller than image '%s', expect size >= %dGB", size, img.ID, img.SizeGiB))
	}
	iops, miBps := r.RootPerformance()
	if err := CheckVolumeShape(r.RootType(), size, iops, miBps); err != nil {
		return 0, err
	}
	return size, nil
}

// RootType is the EBS type RunInstances gives the root volume. A VWS image
// carries no block device mapping, so an omitted type is gp2, the EC2
// CreateVolume default. Normalize keeps an omitted type empty so that the
// idempotency fingerprint of a request without one does not change.
func (r RunInstancesRequest) RootType() VolumeType {
	if r.RootVolumeType == "" {
		return VolumeGP2
	}
	return r.RootVolumeType
}

// RootPerformance is the Iops and Throughput (MiB/s) RunInstances gives the
// root volume: the mapping's values, and for an omitted one what EC2 fills
// in for RootType (3,000 IOPS and 125 MiB/s for gp3, none for the others).
func (r RunInstancesRequest) RootPerformance() (iops, miBps int64) {
	return withDefaultPerformance(r.RootType(), r.RootIops, r.RootThroughput)
}

// MaxUserDataBytes is the EC2 limit on decoded user data.
const MaxUserDataBytes = 16384

// Action returns RunInstances.
func (RunInstancesRequest) Action() Action { return ActionRunInstances }

// Normalize checks the request and fills the default count.
func (r RunInstancesRequest) Normalize() (RunInstancesRequest, error) {
	if r.ImageID.IsZero() {
		return RunInstancesRequest{}, Invalid("imageId", "required")
	}
	typ, ok := vwsInstanceType(r.InstanceType)
	if !ok {
		return RunInstancesRequest{}, Invalid("instanceType", "unsupported instance type")
	}
	r.InstanceType = typ
	switch {
	case len(r.NetworkInterfaces) > 0 && !r.SubnetID.IsZero():
		return RunInstancesRequest{}, InvalidCombination("subnetId",
			"Network interfaces and an instance-level subnet ID may not be specified on the same request")
	case len(r.NetworkInterfaces) > 0:
		nics, err := normalizeInterfaces(r.NetworkInterfaces)
		if err != nil {
			return RunInstancesRequest{}, err
		}
		r.NetworkInterfaces = nics
	case r.SubnetID.IsZero():
		return RunInstancesRequest{}, Invalid("subnetId", "required")
	}
	if r.Count == 0 {
		r.Count = 1
	}
	if r.Count < 1 || r.Count > 10 {
		return RunInstancesRequest{}, Invalid("count", "must be from 1 to 10")
	}
	if err := validRequestTags(r.Tags); err != nil {
		return RunInstancesRequest{}, err
	}
	if len(r.KeyName) > 255 {
		return RunInstancesRequest{}, Invalid("keyName", "malformed")
	}
	if len(r.UserData) > MaxUserDataBytes {
		return RunInstancesRequest{}, Invalid("userData", "exceeds 16384 bytes")
	}
	if !utf8.ValidString(r.UserData) {
		return RunInstancesRequest{}, Invalid("userData", "must be UTF-8 text")
	}
	switch r.RootVolumeType {
	case "", VolumeStandard, VolumeGP2, VolumeGP3, VolumeIO1, VolumeIO2:
	case VolumeST1, VolumeSC1:
		// EC2 CreateVolume: st1 and sc1 volumes can't be used as boot volumes.
		return RunInstancesRequest{}, Invalid("volumeType", "st1 and sc1 cannot be boot volumes")
	default:
		return RunInstancesRequest{}, Invalid("volumeType", "unsupported")
	}
	if err := r.checkRootShape(); err != nil {
		return RunInstancesRequest{}, err
	}
	if err := r.checkExtraVolumes(); err != nil {
		return RunInstancesRequest{}, err
	}
	return r, nil
}

// normalizeInterfaces checks the device indexes and sorts a copy by them,
// so the order the caller listed them in does not change the fingerprint.
// SubnetID is never filled in from NetworkInterfaces, or the reverse, so the
// fingerprint of a request with SubnetID alone stays the same.
func normalizeInterfaces(in []NetworkInterfaceSpec) ([]NetworkInterfaceSpec, error) {
	if len(in) > MaxNetworkInterfaces {
		return nil, Invalid("networkInterfaces", fmt.Sprintf("must list from 1 to %d interfaces", MaxNetworkInterfaces))
	}
	seen := map[int]struct{}{}
	for _, nic := range in {
		if nic.DeviceIndex < 0 || nic.DeviceIndex >= MaxNetworkInterfaces {
			return nil, Invalid("deviceIndex",
				fmt.Sprintf("Value (%d) for parameter deviceIndex is invalid.", nic.DeviceIndex))
		}
		if _, ok := seen[nic.DeviceIndex]; ok {
			return nil, Invalid("deviceIndex", fmt.Sprintf("device index %d is used more than once", nic.DeviceIndex))
		}
		seen[nic.DeviceIndex] = struct{}{}
		if nic.SubnetID.IsZero() {
			return nil, Invalid("subnetId", "each network interface requires a subnet")
		}
	}
	if _, ok := seen[0]; !ok {
		return nil, Invalid("deviceIndex", "a network interface with device index 0 is required")
	}
	// vws-compute wires every interface only when one is direct; with overlay
	// interfaces alone it wires the first and drops the rest (vws-compute#55).
	if len(in) > 1 && !slices.ContainsFunc(in, func(n NetworkInterfaceSpec) bool { return IsDirectSubnet(n.SubnetID) }) {
		return nil, Invalid("networkInterfaces", "more than one network interface requires one on a direct subnet")
	}
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b NetworkInterfaceSpec) int { return cmp.Compare(a.DeviceIndex, b.DeviceIndex) })
	return out, nil
}

// checkExtraVolumes applies the attachment limit, the EC2 device names and
// the CreateVolume per-type rules to the non-root mappings. A device is one
// whether or not it is spelled with /dev/, so xvda is the root device.
func (r RunInstancesRequest) checkExtraVolumes() error {
	if len(r.ExtraVolumes)+1 > MaxLaunchVolumes {
		return AttachmentLimitExceeded(fmt.Sprintf(
			"You've reached the limit on the number of Amazon EBS volumes that can be attached to a single instance: "+
				"a VWS instance takes %d, the root volume included.", MaxLaunchVolumes))
	}
	devices := map[string]struct{}{deviceKey(RootDeviceName): {}}
	for _, v := range r.ExtraVolumes {
		if !ValidDeviceName(v.Device) {
			return Invalid("blockDeviceMapping", v.Device+" is not a valid EBS device name.")
		}
		if _, ok := devices[deviceKey(v.Device)]; ok {
			return Invalid("blockDeviceMapping", "device "+v.Device+" is mapped more than once")
		}
		devices[deviceKey(v.Device)] = struct{}{}
		for _, f := range []struct {
			name string
			v    int64
		}{{"size", v.SizeGiB}, {"iops", v.Iops}, {"throughput", v.Throughput}} {
			if f.v < 0 {
				return Invalid(f.name, fmt.Sprintf("Value (%d) for parameter %s is invalid.", f.v, f.name))
			}
		}
		if v.SizeGiB == 0 {
			// EbsBlockDevice VolumeSize. VWS takes no snapshot (#675), so
			// the size is required.
			return Invalid("blockDeviceMapping", v.Device+": you must specify either a snapshot ID or a volume size")
		}
		if v.Type != "" && !v.Type.Valid() {
			return Invalid("volumeType", "unsupported")
		}
		iops, miBps := v.Performance()
		if err := CheckVolumeShape(v.VolumeType(), v.SizeGiB, iops, miBps); err != nil {
			return err
		}
	}
	return nil
}

// deviceKey is a device name without its optional /dev/ prefix.
func deviceKey(name string) string {
	return strings.TrimPrefix(name, "/dev/")
}

// checkRootShape applies the CreateVolume per-type rules (EC2 API
// Reference, EbsBlockDevice VolumeSize, Iops and Throughput) to the root
// volume with the values it will have. The gp3 defaults change no outcome: gp3 takes
// both parameters.
func (r RunInstancesRequest) checkRootShape() error {
	if r.RootIops < 0 {
		return Invalid("iops", fmt.Sprintf("Value (%d) for parameter iops is invalid.", r.RootIops))
	}
	if r.RootThroughput < 0 {
		return Invalid("throughput", fmt.Sprintf("Value (%d) for parameter throughput is invalid.", r.RootThroughput))
	}
	if r.RootVolumeSize < 0 {
		return Invalid("size", fmt.Sprintf("Value (%d) for parameter size is invalid.", r.RootVolumeSize))
	}
	iops, miBps := r.RootPerformance()
	size := r.RootVolumeSize
	if size == 0 {
		// An omitted size is the image's, which only the backend knows, and
		// RootSizeFor checks the shape again on it. A ratio refused at the
		// largest size the type takes is refused at every size (#429).
		size = limitsOf(r.RootType()).maxGiB
	}
	return CheckVolumeShape(r.RootType(), size, iops, miBps)
}

// StopInstancesRequest stops instances that are running.
type StopInstancesRequest struct {
	IDs []InstanceID `json:"instanceIds"`
}

// Action returns StopInstances.
func (StopInstancesRequest) Action() Action { return ActionStopInstances }

// Normalize checks that at least one id is present.
func (r StopInstancesRequest) Normalize() (StopInstancesRequest, error) {
	if len(r.IDs) < 1 || len(r.IDs) > 20 {
		return StopInstancesRequest{}, Invalid("instanceIds", "must list from 1 to 20 ids")
	}
	seen := map[InstanceID]struct{}{}
	for _, id := range r.IDs {
		if id.IsZero() {
			return StopInstancesRequest{}, Invalid("instanceIds", "malformed")
		}
		if _, ok := seen[id]; ok {
			return StopInstancesRequest{}, Invalid("instanceIds", "duplicate")
		}
		seen[id] = struct{}{}
	}
	return r, nil
}

// InstanceQuery selects instances.
type InstanceQuery struct {
	IDs    []InstanceID    `json:"instanceIds,omitempty"`
	States []InstanceState `json:"states,omitempty"`
	Page   PageRequest     `json:"page,omitempty"`
}

// Normalize canonicalizes the query.
func (q InstanceQuery) Normalize() (InstanceQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return InstanceQuery{}, err
	}
	q.Page = page
	if len(q.IDs) > 100 {
		return InstanceQuery{}, Invalid("instanceIds", "too many")
	}
	return q, nil
}

// InstanceType is one machine type vws-compute runs.
type InstanceType struct {
	Name      string `json:"instanceType"`
	VCPUs     int    `json:"vcpus"`
	MemoryMiB int    `json:"memoryMiB"`
}

// InstanceTypes is the vws-compute machine catalog, smallest first.
// vws-compute has no RPC that lists it; keep it in step with vwsInstanceType.
func InstanceTypes() []InstanceType {
	return []InstanceType{
		{Name: "vws.small", VCPUs: 1, MemoryMiB: 1024},
		{Name: "vws.medium", VCPUs: 2, MemoryMiB: 4096},
		{Name: "vws.large", VCPUs: 4, MemoryMiB: 8192},
		{Name: "vws.xlarge", VCPUs: 8, MemoryMiB: 16384},
	}
}

// vwsInstanceType maps an EC2 instance type to the vws-compute machine type
// nearest by vCPU and memory. vws-compute accepts only vws.small (1 vCPU,
// 1 GiB), vws.medium (2, 4 GiB), vws.large (4, 8 GiB), and vws.xlarge
// (8, 16 GiB). Nearest is the least |log2 vCPU ratio| + |log2 memory ratio|;
// a tie takes the smaller type. A vws name maps to itself.
func vwsInstanceType(s string) (string, bool) {
	switch s {
	case "vws.small", "vws.medium", "vws.large", "vws.xlarge":
		return s, true
	case "t2.nano", "t2.micro", "t2.small", "t3.nano", "t3.micro", "t3a.nano", "t3a.micro":
		return "vws.small", true
	case "t2.medium", "t2.large", "t3.small", "t3.medium", "t3.large",
		"t3a.small", "t3a.medium", "t3a.large", "m5.large", "c5.large":
		return "vws.medium", true
	case "t2.xlarge", "t3.xlarge", "t3a.xlarge", "m5.xlarge", "c5.xlarge":
		return "vws.large", true
	case "t2.2xlarge", "t3.2xlarge", "t3a.2xlarge", "m5.2xlarge", "c5.2xlarge":
		return "vws.xlarge", true
	}
	return "", false
}

// CreateTagsRequest adds or overwrites tags on instances. Other tags stay.
type CreateTagsRequest struct {
	IDs  []InstanceID      `json:"instanceIds"`
	Tags map[string]string `json:"tags"`
}

// Action returns CreateTags.
func (CreateTagsRequest) Action() Action { return ActionCreateTags }

// Normalize checks the ids and the tags.
func (r CreateTagsRequest) Normalize() (CreateTagsRequest, error) {
	if err := instanceIDs(r.IDs); err != nil {
		return CreateTagsRequest{}, err
	}
	if len(r.Tags) == 0 {
		return CreateTagsRequest{}, Invalid("tags", "required")
	}
	if err := validRequestTags(r.Tags); err != nil {
		return CreateTagsRequest{}, err
	}
	return r, nil
}

// MergeTags returns base with add written over it, checked as one tag set.
func MergeTags(base, add map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(base)+len(add))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	if err := validTags(out); err != nil {
		return nil, err
	}
	return out, nil
}

// MaxTags is the user tag limit per resource, as in EC2 ("You can assign up
// to 50 tags to a resource"). The gRPC backend stores tags as compute labels
// and keeps room for them next to its own labels (#303).
const MaxTags = 50

func validTags(tags map[string]string) error {
	if len(tags) > MaxTags {
		return Invalid("tags", "too many")
	}
	for k, v := range tags {
		if n := utf8.RuneCountInString(k); n < 1 || n > 128 || !tagText(k) {
			return Invalid("tags", "malformed key")
		}
		if utf8.RuneCountInString(v) > 256 || !tagText(v) {
			return Invalid("tags", "malformed value")
		}
	}
	return nil
}

// validRequestTags is validTags for the tags a request sets. EC2 keeps aws:
// keys, in any case, for itself, so a request may not set one; a resource
// that already has one can still take other tags.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#tag-restrictions
func validRequestTags(tags map[string]string) error {
	for k := range tags {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return Invalid("tags", "reserved")
		}
	}
	return validTags(tags)
}

// tagText reports whether s is valid UTF-8 with no control characters.
// As in EC2, lengths count characters and spaces are allowed.
func tagText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// NextInstanceState is the state an instance reaches when action finishes.
// The accept-time state is the transitional one. A zero transitional state
// means the action does not apply.
func NextInstanceState(action Action, from InstanceState) (transitional, settled InstanceState, err error) {
	switch action {
	case ActionStopInstances:
		switch from {
		case InstanceRunning:
			return InstanceStopping, InstanceStopped, nil
		case InstanceStopped:
			return InstanceStopped, InstanceStopped, nil
		case InstancePending, InstanceStopping, InstanceShuttingDown, InstanceTerminated, instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be stopped from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be stopped from "+from.String())
		}
	case ActionStartInstances:
		switch from {
		case InstanceStopped:
			return InstancePending, InstanceRunning, nil
		case InstancePending, InstanceRunning, InstanceStopping, InstanceShuttingDown, InstanceTerminated, instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be started from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be started from "+from.String())
		}
	case ActionTerminateInstances:
		switch from {
		case InstanceTerminated:
			return InstanceTerminated, InstanceTerminated, nil
		case InstancePending, InstanceRunning, InstanceStopping, InstanceStopped, InstanceShuttingDown:
			return InstanceShuttingDown, InstanceTerminated, nil
		case instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be terminated from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be terminated from "+from.String())
		}
	case ActionRunInstances, ActionCreateSubnet, ActionCreateVpc, ActionDeleteVpc,
		ActionCreateVolume, ActionAttachVolume, ActionDeleteVolume, ActionCreateSecurityGroup,
		ActionAuthorizeSecurityGroupIngress, ActionCreateKeyPair, ActionDeleteKeyPair,
		ActionDeleteSecurityGroup, ActionDeleteSubnet, ActionAllocateAddress, ActionReleaseAddress,
		ActionCreateSnapshot, ActionDeleteSnapshot, ActionAssociateAddress, ActionDisassociateAddress,
		ActionModifyVolume, ActionCreateTags, ActionDetachVolume, ActionRevokeSecurityGroupIngress,
		ActionDeleteTags, actionNone:
		return 0, 0, Invalid("action", "not an instance transition")
	default:
		return 0, 0, Invalid("action", "not an instance transition")
	}
}
