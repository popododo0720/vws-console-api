// Package proxmox is the Proxmox VE backend. ids.go computes every EC2
// identifier from Proxmox data alone, so VWS keeps no id mapping.
package proxmox

import (
	"crypto/sha256"
	"encoding/hex"
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

// IDs computes the identifiers of one cluster.
type IDs struct {
	cluster string
	hash    HashFunc
}

// NewIDs returns the identifier rules of the named cluster.
func NewIDs(cluster string) IDs { return IDs{cluster: cluster, hash: sha256Hex} }

// VM is what Proxmox says identifies a VM. UUID is the smbios1 uuid and Ctime
// is the digits of meta.ctime; either may be empty.
type VM struct {
	UUID  string
	VMID  int
	Ctime string
}

// Instance returns the i- id of vm. The VMID is an input only when the VM
// has no uuid, because Proxmox reuses VMIDs.
func (c IDs) Instance(vm VM) (resource.InstanceID, IDSource, error) {
	var hex string
	var src IDSource
	switch {
	case vm.UUID != "":
		hex, src = c.digest("vws-pve-instance-v1", vm.UUID), SourceUUID
	case vm.Ctime != "":
		hex, src = c.digest(instanceFallback, strconv.Itoa(vm.VMID), vm.Ctime), SourceFallback
	default:
		hex, src = c.digest(instanceFallback, strconv.Itoa(vm.VMID), "nometa"), SourceVMID
	}
	id, err := resource.Parse[resource.InstanceID]("i-" + hex)
	return id, src, wrap("instance", err)
}

// Image returns the ami- id of the template with the given uuid.
func (c IDs) Image(uuid string) (resource.ImageID, error) {
	id, err := resource.Parse[resource.ImageID]("ami-" + c.digest("vws-pve-image-v1", uuid))
	return id, wrap("image", err)
}

// UnknownImage returns the ami- id of a VM whose image is not known.
func (c IDs) UnknownImage() (resource.ImageID, error) { return c.Image("unknown") }

// Snapshot returns the snap- id of a snapshot of the VM with the given uuid.
func (c IDs) Snapshot(uuid, snapname string) (resource.SnapshotID, error) {
	id, err := resource.Parse[resource.SnapshotID]("snap-" + c.digest("vws-pve-snapshot-v1", uuid, snapname))
	return id, wrap("snapshot", err)
}

// Reservation returns the r- id of a launch key.
func (c IDs) Reservation(key string) (resource.ReservationID, error) {
	id, err := resource.Parse[resource.ReservationID]("r-" + c.digest("vws-pve-reservation-v1", key))
	return id, wrap("reservation", err)
}

// VolumeSerial returns the drive serial of a volume VWS creates for a launch
// key at index. The volume id is "vol-" and the serial.
func (c IDs) VolumeSerial(key string, index int) string {
	return c.digest("vws-pve-volume-v1", key, strconv.Itoa(index))
}

// RootVolumeSerial returns the drive serial of the root volume of the
// instance with the given uuid.
func (c IDs) RootVolumeSerial(uuid string) string {
	return c.digest("vws-pve-volume-v1", uuid, "root")
}

// Volume returns the vol- id of a drive. A serial VWS wrote (17 hex digits)
// is the id; any other drive is named by storage and volname.
func (c IDs) Volume(serial, storage, volname string) (resource.VolumeID, IDSource, error) {
	serial = strings.ToLower(serial)
	if len(serial) == idHexLen {
		if id, err := resource.Parse[resource.VolumeID]("vol-" + serial); err == nil {
			return id, SourceSerial, nil
		}
	}
	id, err := resource.Parse[resource.VolumeID]("vol-" + c.digest("vws-pve-volume-v1", storage, volname))
	return id, SourceVolname, wrap("volume", err)
}

// BridgeVPC returns the vpc- id of the default VPC of a bridge.
func (c IDs) BridgeVPC(iface string) (resource.VpcID, error) {
	id, err := resource.Parse[resource.VpcID]("vpc-" + c.digest("vws-pve-vpc-v1", "bridge", iface))
	return id, wrap("vpc", err)
}

// BridgeSubnet returns the subnet- id of the subnet of a bridge's default VPC.
func (c IDs) BridgeSubnet(iface, cidr string) (resource.SubnetID, error) {
	id, err := resource.Parse[resource.SubnetID]("subnet-" + c.digest("vws-pve-subnet-v1", "bridge", iface, cidr))
	return id, wrap("subnet", err)
}

// SDNVPC returns the vpc- id of an SDN VNet.
func (c IDs) SDNVPC(zone, vnet string) (resource.VpcID, error) {
	id, err := resource.Parse[resource.VpcID]("vpc-" + c.digest("vws-pve-vpc-v1", zone, vnet))
	return id, wrap("vpc", err)
}

// SDNSubnet returns the subnet- id of a subnet of an SDN VNet.
func (c IDs) SDNSubnet(vnet, cidr string) (resource.SubnetID, error) {
	id, err := resource.Parse[resource.SubnetID]("subnet-" + c.digest("vws-pve-subnet-v1", vnet, cidr))
	return id, wrap("subnet", err)
}

// SecurityGroup returns the sg- id of a firewall security group.
func (c IDs) SecurityGroup(group string) (resource.SecurityGroupID, error) {
	id, err := resource.Parse[resource.SecurityGroupID]("sg-" + c.digest("vws-pve-sg-v1", group))
	return id, wrap("security group", err)
}

// digest is the first 17 hex digits of H(domain || cluster || parts...): the
// inputs lower-cased and joined by NUL.
func (c IDs) digest(domain string, parts ...string) string {
	in := strings.ToLower(strings.Join(append([]string{domain, c.cluster}, parts...), "\x00"))
	return c.hash(in)[:idHexLen]
}

func wrap(what string, err error) error {
	if err != nil {
		return fmt.Errorf("proxmox: compute %s id: %w", what, err)
	}
	return nil
}

// Row is one inventory row's identifier and where it came from.
type Row struct {
	ID     string
	Source IDSource
}

// MarkCollisions sets SourceCollision on every row whose ID another row also
// has. Two VMs with one id would be one instance to the API.
func MarkCollisions(rows []Row) {
	seen := make(map[string]int, len(rows))
	for _, r := range rows {
		seen[r.ID]++
	}
	for i := range rows {
		if seen[rows[i].ID] > 1 {
			rows[i].Source = SourceCollision
		}
	}
}
