// Package seed builds the NoCloud seed image that a guest's cloud-init reads
// on first boot: an ISO 9660 image labelled "cidata" with meta-data,
// user-data and, for a static address, network-config.
//
// It uses the standard library only and never touches the file system, so
// user data never lands in a temporary file. The image is a pure function of
// Seed: the same Seed gives the same bytes.
package seed

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// MaxUserData is the largest user data ISO accepts.
const MaxUserData = 64 << 10

// Seed is everything a guest learns at first boot.
type Seed struct {
	// InstanceID is the meta-data instance-id and local-hostname: "i-" and
	// 17 hex digits.
	InstanceID string
	// PublicKey is the one meta-data public-keys entry, "<algo> <base64>".
	// Empty writes no public-keys.
	PublicKey string
	// Network is set for a static subnet. Nil writes no network-config, and
	// cloud-init falls back to DHCP on the first interface.
	Network *Static
	// UserData is written unchanged. Nil writes an empty user-data, because
	// NoCloud requires the file.
	UserData []byte
}

// Static is the address of net0.
type Static struct {
	MAC         net.HardwareAddr // from net0; written in lower case
	Address     netip.Prefix     // ipconfig0 ip=
	Gateway     netip.Addr       // ipconfig0 gw=
	Nameservers []netip.Addr     // region.yaml, 1 to 3
}

var (
	instanceID = regexp.MustCompile(`^i-[0-9a-f]{17}$`)
	publicKey  = regexp.MustCompile(`^[a-z0-9][a-z0-9.@-]{0,63} ([A-Za-z0-9+/]+={0,2})$`)
)

// ISO returns the seed image. It refuses a Seed it cannot write exactly: an
// InstanceID that is not "i-" and 17 hex digits, a PublicKey that is not
// "<algo> <base64>", a MAC that is not 6 bytes, a Static without an IPv4
// address, an IPv4 gateway and 1 to 3 IPv4 nameservers, and user data over
// MaxUserData. Its errors never carry the key or the user data.
func (s Seed) ISO() ([]byte, error) {
	files, err := s.files()
	if err != nil {
		return nil, err
	}
	return image(files), nil
}

// file is one entry of the root directory.
type file struct {
	name string // "meta-data", "network-config" or "user-data"
	data []byte
}

// files renders the texts, in the order of their names. Every value comes
// from a closed alphabet (hex, base64, dotted quads), so the files are written
// from fixed templates: there is no YAML library and nothing to escape.
// network-config is the text PVE itself writes (qemu-server Cloudinit.pm,
// nocloud_network), so a template boots as it does today.
func (s Seed) files() ([]file, error) {
	if !instanceID.MatchString(s.InstanceID) {
		return nil, errors.New("seed: instance id is not i- and 17 hex digits")
	}
	meta := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", s.InstanceID, s.InstanceID)
	if s.PublicKey != "" {
		m := publicKey.FindStringSubmatch(s.PublicKey)
		if m == nil {
			return nil, errors.New("seed: public key is not <algo> <base64>")
		}
		if _, err := base64.StdEncoding.DecodeString(m[1]); err != nil {
			return nil, errors.New("seed: public key is not <algo> <base64>")
		}
		meta += "public-keys:\n- '" + s.PublicKey + "'\n"
	}
	if len(s.UserData) > MaxUserData {
		return nil, fmt.Errorf("seed: user data exceeds %d bytes", MaxUserData)
	}
	files := []file{{name: "meta-data", data: []byte(meta)}}
	if s.Network != nil {
		config, err := s.Network.config()
		if err != nil {
			return nil, err
		}
		files = append(files, file{name: "network-config", data: config})
	}
	return append(files, file{name: "user-data", data: s.UserData}), nil
}

// config is network-config version 1 for eth0, matched by its MAC.
func (n *Static) config() ([]byte, error) {
	if len(n.MAC) != 6 {
		return nil, errors.New("seed: MAC is not 6 bytes")
	}
	if !n.Address.IsValid() || !n.Address.Addr().Is4() {
		return nil, errors.New("seed: address is not an IPv4 prefix")
	}
	if !n.Gateway.Is4() {
		return nil, errors.New("seed: gateway is not an IPv4 address")
	}
	if len(n.Nameservers) < 1 || len(n.Nameservers) > 3 {
		return nil, errors.New("seed: expected 1 to 3 nameservers")
	}
	var b strings.Builder
	fmt.Fprintf(&b, `version: 1
config:
    - type: physical
      name: eth0
      mac_address: '%s'
      subnets:
      - type: static
        address: '%s'
        netmask: '%s'
        gateway: '%s'
    - type: nameserver
      address:
`, n.MAC, n.Address.Addr(), net.IP(net.CIDRMask(n.Address.Bits(), 32)), n.Gateway)
	for _, ns := range n.Nameservers {
		if !ns.Is4() {
			return nil, errors.New("seed: nameserver is not an IPv4 address")
		}
		fmt.Fprintf(&b, "      - '%s'\n", ns)
	}
	return []byte(b.String()), nil
}
