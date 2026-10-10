package grpcclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Label keys carried on the resource API. They are not caller tags.
const (
	labelFingerprint = "vws-fingerprint"
	labelImage       = "vws-image"
	labelReservation = "vws-reservation"
	labelLaunch      = "vws-launch"
)

const labelPrefix = "vws-"

// project is the resource-API project for an account. A bare account id is
// twelve digits, which is not a resource id, so the project is "a" plus the
// account. accountOf reverses that.
func project(account resource.AccountID) string { return "a" + account.String() }

func accountOf(projectID string) (resource.AccountID, error) {
	rest, ok := strings.CutPrefix(projectID, "a")
	if !ok || rest == projectID {
		return resource.AccountID{}, resource.Internal(strErr("bad project"))
	}
	account, err := resource.Parse[resource.AccountID](rest)
	if err != nil {
		return resource.AccountID{}, resource.Internal(err)
	}
	return account, nil
}

func projectOfName(name string) (string, error) {
	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] != "projects" || parts[1] == "" {
		return "", resource.Internal(strErr("bad resource name"))
	}
	return parts[1], nil
}

func instanceParent(projectID string) string {
	return "projects/" + projectID + "/zones/" + resource.ZoneName
}

func instanceName(projectID, id string) string {
	return instanceParent(projectID) + "/instances/" + id
}

func volumeParent(projectID string) string { return instanceParent(projectID) }

func volumeName(projectID, id string) string {
	return volumeParent(projectID) + "/volumes/" + id
}

func imageName(projectID, id string) string {
	return "projects/" + projectID + "/regions/" + resource.RegionName + "/images/" + id
}

func regionParent(projectID string) string {
	return "projects/" + projectID + "/regions/" + resource.RegionName
}

func vpcName(projectID, id string) string {
	return regionParent(projectID) + "/vpcs/" + id
}

func subnetParent(projectID, vpcID string) string {
	return vpcName(projectID, vpcID) + "/subnets"
}

func subnetName(projectID, vpcID, id string) string {
	return subnetParent(projectID, vpcID) + "/" + id
}

func bucketParent(projectID string) string { return "projects/" + projectID }

func bucketName(projectID, name string) string {
	return bucketParent(projectID) + "/buckets/" + name
}

func objectName(projectID, bucket, key string) string {
	return bucketName(projectID, bucket) + "/objects/" + encodeObjectKey(key)
}

func operationName(projectID, local string) string {
	return "projects/" + projectID + "/operations/" + local
}

func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// operationLocal accepts a 16- or 32-digit hex segment, or a UUID with dashes.
func operationLocal(name string) (string, error) {
	seg := strings.ReplaceAll(lastSegment(name), "-", "")
	if len(seg) != 16 && len(seg) != 32 {
		return "", resource.Internal(strErr("bad operation name"))
	}
	for _, r := range seg {
		if !isHexChar(r) {
			return "", resource.Internal(strErr("bad operation name"))
		}
	}
	return seg, nil
}

func isHexChar(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

// vpcForCIDR is the VPC that contains cidr. The parent prefix is eight bits
// shorter, and a /0 parent is rejected.
func vpcForCIDR(cidr string) (id, vpcCIDR string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return "", "", resource.Invalid("cidrBlock", "must be an ipv4 network")
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones <= 0 || ones > 32 {
		return "", "", resource.Invalid("cidrBlock", "must be an ipv4 network")
	}
	parent := ones - 8
	if parent < 0 {
		parent = 0
	}
	if parent == 0 || parent >= ones {
		return "", "", resource.Invalid("cidrBlock", "needs a containing network")
	}
	mask := net.CIDRMask(parent, 32)
	network := ip.To4().Mask(mask)
	vpcCIDR = (&net.IPNet{IP: network, Mask: mask}).String()
	id = "vpc-" + strings.NewReplacer(".", "-", "/", "-").Replace(vpcCIDR)
	return id, vpcCIDR, nil
}

// requestUUID is a UUID version 4 derived from parts. The same parts always
// produce the same id, so a retry hits the original operation.
func requestUUID(parts ...string) string {
	sum := hashParts(parts...)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// derivedID is prefix plus 17 hex digits. The server may mint a different id;
// callers use the name in the operation metadata.
func derivedID(prefix string, parts ...string) string {
	sum := hashParts(parts...)
	return prefix + hex.EncodeToString(sum[:])[:17]
}

func hashParts(parts ...string) [32]byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func encodeObjectKey(key string) string { return url.PathEscape(key) }

func decodeObjectKey(key string) (string, error) {
	plain, err := url.PathUnescape(key)
	if err != nil {
		return "", resource.Internal(err)
	}
	return plain, nil
}

func labelOK(key, value string) bool {
	if key == "" || strings.HasPrefix(key, labelPrefix) || len(key) > 63 || len(value) > 63 {
		return false
	}
	for i, r := range key {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func userTags(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range labels {
		if strings.HasPrefix(key, labelPrefix) {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func withInternalLabels(tags map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range extra {
		out[key] = value
	}
	for key, value := range tags {
		if labelOK(key, value) {
			out[key] = value
		}
	}
	return out
}
