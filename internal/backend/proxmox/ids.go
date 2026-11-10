// Package proxmox is the Proxmox VE backend. ids.go computes every EC2
// identifier from Proxmox data alone, so VWS keeps no id mapping.
package proxmox

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IDSource says what an identifier was computed from.
type IDSource string

// The values of IDSource.
const (
	// SourceUUID: the VM's smbios1 uuid.
	SourceUUID IDSource = "uuid"
	// SourceSerial: a drive serial VWS wrote.
	SourceSerial IDSource = "serial"
	// SourceFallback: VMID and meta.ctime, for a VM without a uuid.
	SourceFallback IDSource = "fallback"
	// SourceVMID: VMID alone, for a VM without a uuid or meta.ctime.
	SourceVMID IDSource = "vmid"
	// SourceVolname: storage and volume name, so a rename changes the id.
	SourceVolname IDSource = "volname"
	// SourceCollision: another row of the same inventory has this id.
	SourceCollision IDSource = "collision"
)

// ErrInput is wrapped by every error for Proxmox data no id can be computed
// from: an empty or NUL-holding part, a malformed uuid, ctime or VMID. An
// empty part would make unrelated resources share one id.
var ErrInput = errors.New("proxmox: id input")

const (
	idHexLen         = 17
	instanceFallback = "vws-pve-instance-fallback-v1"
)

// HashFunc returns the lower-case hex digest of s, at least 17 digits long.
type HashFunc func(s string) string

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// IDs computes the identifiers of one cluster. Its zero value computes none.
type IDs struct {
	cluster string
	hash    HashFunc
}

// NewIDs returns the identifier rules of the named cluster. An empty name
// would give equal ids in every region, so it is refused.
func NewIDs(cluster string) (IDs, error) {
	if err := checkPart(cluster); err != nil {
		return IDs{}, fmt.Errorf("proxmox: cluster name: %w", err)
	}
	return IDs{cluster: cluster, hash: sha256Hex}, nil
}

// VM is what Proxmox says identifies a VM. UUID is the smbios1 uuid,
// 8-4-4-4-12 hex digits and not all zeros, and Ctime is meta.ctime in
// decimal; either may be empty when Proxmox has none.
type VM struct {
	UUID  string
	VMID  int
	Ctime string
}

// Instance returns the i- id of vm. The VMID is an input only when the VM
// has no uuid, because Proxmox reuses VMIDs.
func (c IDs) Instance(vm VM) (resource.InstanceID, IDSource, error) {
	var id resource.InstanceID
	var err error
	switch {
	case vm.UUID != "":
		if err = checkUUID(vm.UUID); err == nil {
			id, err = derive[resource.InstanceID](c, "i-", "vws-pve-instance-v1", vm.UUID)
		}
		return id, SourceUUID, err
	case vm.VMID < 1:
		return id, "", fmt.Errorf("%w: VMID %d", ErrInput, vm.VMID)
	case vm.Ctime != "":
		if n, perr := strconv.ParseUint(vm.Ctime, 10, 64); perr != nil || strconv.FormatUint(n, 10) != vm.Ctime {
			return id, "", fmt.Errorf("%w: meta.ctime %q is not decimal", ErrInput, vm.Ctime)
		}
		id, err = derive[resource.InstanceID](c, "i-", instanceFallback, strconv.Itoa(vm.VMID), vm.Ctime)
		return id, SourceFallback, err
	default:
		id, err = derive[resource.InstanceID](c, "i-", instanceFallback, strconv.Itoa(vm.VMID), "nometa")
		return id, SourceVMID, err
	}
}

// Image returns the ami- id of the template with the given uuid. A template
// without a uuid has no id: design 4.3 gives a fallback only for instances.
func (c IDs) Image(uuid string) (resource.ImageID, error) {
	if err := checkUUID(uuid); err != nil {
		return resource.ImageID{}, err
	}
	return derive[resource.ImageID](c, "ami-", "vws-pve-image-v1", uuid)
}

// UnknownImage returns the ami- id of a VM whose image is not known. No
// template has it, because "unknown" is not a uuid.
func (c IDs) UnknownImage() (resource.ImageID, error) {
	return derive[resource.ImageID](c, "ami-", "vws-pve-image-v1", "unknown")
}

// Snapshot returns the snap- id of a snapshot of the VM with the given uuid.
func (c IDs) Snapshot(uuid, snapname string) (resource.SnapshotID, error) {
	if err := checkUUID(uuid); err != nil {
		return resource.SnapshotID{}, err
	}
	return derive[resource.SnapshotID](c, "snap-", "vws-pve-snapshot-v1", uuid, snapname)
}

// Reservation returns the r- id of a launch key.
func (c IDs) Reservation(key string) (resource.ReservationID, error) {
	return derive[resource.ReservationID](c, "r-", "vws-pve-reservation-v1", key)
}

// VolumeSerial returns the drive serial of a volume VWS creates for a launch
// key at index. The volume id is "vol-" and the serial.
func (c IDs) VolumeSerial(key string, index int) (string, error) {
	if index < 0 {
		return "", fmt.Errorf("%w: volume index %d", ErrInput, index)
	}
	return c.digest("vws-pve-volume-v1", key, strconv.Itoa(index))
}

// RootVolumeSerial returns the drive serial of the root volume of the
// instance with the given uuid.
func (c IDs) RootVolumeSerial(uuid string) (string, error) {
	if err := checkUUID(uuid); err != nil {
		return "", err
	}
	return c.digest("vws-pve-volume-v1", uuid, "root")
}

// Volume returns the vol- id of a drive. serial is the drive's serial option
// already URL-decoded. A serial of 17 hex digits, the form VWS writes, is the
// id; any other drive, a foreign serial included, is named by storage and
// volname.
func (c IDs) Volume(serial, storage, volname string) (resource.VolumeID, IDSource, error) {
	serial = strings.ToLower(serial)
	if len(serial) == idHexLen && strings.Trim(serial, "0123456789abcdef") == "" {
		id, err := resource.Parse[resource.VolumeID]("vol-" + serial)
		return id, SourceSerial, wrap("vol-", err)
	}
	id, err := derive[resource.VolumeID](c, "vol-", "vws-pve-volume-name-v1", storage, volname)
	return id, SourceVolname, err
}

// BridgeVPC returns the vpc- id of the default VPC of a bridge.
func (c IDs) BridgeVPC(iface string) (resource.VpcID, error) {
	return derive[resource.VpcID](c, "vpc-", "vws-pve-vpc-v1", "bridge", iface)
}

// BridgeSubnet returns the subnet- id of the subnet of a bridge's default VPC.
func (c IDs) BridgeSubnet(iface, cidr string) (resource.SubnetID, error) {
	return derive[resource.SubnetID](c, "subnet-", "vws-pve-subnet-v1", "bridge", iface, cidr)
}

// SDNVPC returns the vpc- id of an SDN VNet.
func (c IDs) SDNVPC(zone, vnet string) (resource.VpcID, error) {
	return derive[resource.VpcID](c, "vpc-", "vws-pve-sdn-vpc-v1", zone, vnet)
}

// SDNSubnet returns the subnet- id of a subnet of an SDN VNet.
func (c IDs) SDNSubnet(vnet, cidr string) (resource.SubnetID, error) {
	return derive[resource.SubnetID](c, "subnet-", "vws-pve-sdn-subnet-v1", vnet, cidr)
}

// SecurityGroup returns the sg- id of a firewall security group.
func (c IDs) SecurityGroup(group string) (resource.SecurityGroupID, error) {
	return derive[resource.SecurityGroupID](c, "sg-", "vws-pve-sg-v1", group)
}

type textID[T any] interface {
	*T
	encoding.TextUnmarshaler
}

// derive returns the id prefix and digest(domain, parts...), parsed as T.
func derive[T any, PT textID[T]](c IDs, prefix, domain string, parts ...string) (T, error) {
	digest, err := c.digest(domain, parts...)
	if err != nil {
		var zero T
		return zero, wrap(prefix, err)
	}
	id, err := resource.Parse[T, PT](prefix + digest)
	return id, wrap(prefix, err)
}

// digest is the first 17 hex digits of H(domain || cluster || parts...): the
// inputs lower-cased and joined by NUL. The join is one-to-one only because
// no part is empty or holds a NUL.
func (c IDs) digest(domain string, parts ...string) (string, error) {
	if c.hash == nil {
		return "", fmt.Errorf("%w: IDs not made by NewIDs", ErrInput)
	}
	for _, p := range parts {
		if err := checkPart(p); err != nil {
			return "", err
		}
	}
	in := strings.ToLower(strings.Join(append([]string{domain, c.cluster}, parts...), "\x00"))
	sum := c.hash(in)
	if len(sum) < idHexLen {
		return "", fmt.Errorf("proxmox: hash gave %d hex digits, want at least %d", len(sum), idHexLen)
	}
	return sum[:idHexLen], nil
}

func checkPart(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%w: empty part", ErrInput)
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("%w: part %q holds a NUL", ErrInput, p)
	}
	return nil
}

// checkUUID accepts an smbios1 uuid, 8-4-4-4-12 hex digits in either case.
// An all-zero uuid is shared by hand-written configs, so it is refused.
func checkUUID(uuid string) error {
	shape := len(uuid) == 36
	for i := 0; shape && i < len(uuid); i++ {
		dash := i == 8 || i == 13 || i == 18 || i == 23
		shape = dash == (uuid[i] == '-') && (dash || strings.IndexByte("0123456789abcdefABCDEF", uuid[i]) >= 0)
	}
	if !shape || strings.Trim(uuid, "0-") == "" {
		return fmt.Errorf("%w: uuid %q", ErrInput, uuid)
	}
	return nil
}

func wrap(prefix string, err error) error {
	if err != nil {
		return fmt.Errorf("proxmox: compute %s id: %w", strings.TrimSuffix(prefix, "-"), err)
	}
	return nil
}

// Row is one inventory row's identifier and where it came from.
type Row struct {
	Ref    resource.Ref
	Source IDSource
}

// MarkCollisions sets SourceCollision on every row whose Ref another row also
// has, replacing its source. Two VMs with one id would be one instance to the
// API. The caller passes one row per Proxmox object (a bridge seen on every
// node is one row) and the whole region's listing, before a pool filter or a
// page, or a duplicate in another pool hides.
func MarkCollisions(rows []Row) {
	seen := make(map[resource.Ref]int, len(rows))
	for _, r := range rows {
		seen[r.Ref]++
	}
	for i := range rows {
		if seen[rows[i].Ref] > 1 {
			rows[i].Source = SourceCollision
		}
	}
}
