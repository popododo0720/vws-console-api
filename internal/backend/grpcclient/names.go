package grpcclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Label keys carried on the resource API. They are not caller tags.
const (
	labelFingerprint = "vws-fingerprint"
	labelImage       = "vws-image"
	labelAction      = "vws-action"
	labelReservation = "vws-reservation"
	labelLaunch      = "vws-launch"
	// labelInstance on a boot volume names the instance it was made for.
	labelInstance = "vws-instance"
	// labelNameTag carries the EC2 Name tag. Label keys are lowercase, so the
	// key "Name" cannot be stored as is.
	labelNameTag = "vws-name"
)

// nameTag is the EC2 tag the console shows as the resource name.
const nameTag = "Name"

const labelPrefix = "vws-"

// project is the resource-API project for an account. A bare account id is
// twelve digits, which is not a resource id, so the project is "a" plus the
// account. accountOf reverses that.
func project(account resource.AccountID) string { return "a" + account.String() }

func accountOf(projectID string) (resource.AccountID, error) {
	rest, ok := strings.CutPrefix(projectID, "a")
	if !ok || rest == projectID {
		return resource.AccountID{}, resource.Internal(errors.New("bad project"))
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
		return "", resource.Internal(errors.New("bad resource name"))
	}
	return parts[1], nil
}

func accountIn(name string) (resource.AccountID, error) {
	projectID, err := projectOfName(name)
	if err != nil {
		return resource.AccountID{}, err
	}
	return accountOf(projectID)
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

func securityGroupName(projectID, vpcID, id string) string {
	return vpcName(projectID, vpcID) + "/securityGroups/" + id
}

func keyPairName(projectID, id string) string {
	return regionParent(projectID) + "/keyPairs/" + id
}

func addressName(projectID, id string) string {
	return regionParent(projectID) + "/addresses/" + id
}

func snapshotName(projectID, id string) string {
	return regionParent(projectID) + "/snapshots/" + id
}

func bucketParent(projectID string) string { return "projects/" + projectID }

func bucketName(projectID, name string) string {
	return bucketParent(projectID) + "/buckets/" + name
}

func objectName(projectID, bucket, key string) string {
	return bucketName(projectID, bucket) + "/objects/" + encodeObjectKey(key)
}

func operationName(projectID, local string) string {
	return "projects/" + projectID + "/operations/" + canonicalOperationSegment(local)
}

// canonicalOperationSegment is the last path segment this process sends back
// to the service that minted local. Storage and compute publish op- plus 20
// hex digits; network publishes op- plus its own hex width. Any width from
// 16 to 40, other than a 32-digit UUID, goes back out with that prefix. A
// 32-digit id is the lowercase UUID the proto contract names.
func canonicalOperationSegment(local string) string {
	if len(local) == 32 && isHexString(local, 32) {
		return local[0:8] + "-" + local[8:12] + "-" + local[12:16] + "-" + local[16:20] + "-" + local[20:32]
	}
	if operationHexWidth(len(local)) && isHexString(local, len(local)) {
		return "op-" + local
	}
	return local
}

func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// operationLocal reads the operation id the resource services publish.
// The segment is op- plus 16 to 40 lowercase hex digits, a bare hex string of
// that width, or a lowercase UUID. Storage and compute use 20 digits.
// Anything else is rejected.
func operationLocal(name string) (string, error) {
	local, ok := parseOperationSegment(lastSegment(name))
	if !ok {
		return "", resource.Internal(fmt.Errorf("bad operation name %q", name))
	}
	return local, nil
}

func parseOperationSegment(seg string) (string, bool) {
	if rest, ok := strings.CutPrefix(seg, "op-"); ok {
		seg = rest
	}
	if operationHexWidth(len(seg)) && isHexString(seg, len(seg)) {
		return seg, true
	}
	if len(seg) == 36 && seg[8] == '-' && seg[13] == '-' && seg[18] == '-' && seg[23] == '-' {
		raw := strings.ReplaceAll(seg, "-", "")
		if isHexString(raw, 32) {
			return raw, true
		}
	}
	return "", false
}

func operationHexWidth(n int) bool {
	return n >= 16 && n <= 40
}

func isHexString(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !isHexChar(r) {
			return false
		}
	}
	return true
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

func labelName(labels map[string]string) string {
	keys := []string{"keyname", "keyname2", "keyname3", "keyname4", "keyname5"}
	var b strings.Builder
	for _, key := range keys {
		part := labels[key]
		if part == "" {
			break
		}
		b.WriteString(part)
	}
	return b.String()
}

// Tags that are valid labels are stored as plain labels, so compute can
// filter on them. Every other tag (uppercase or punctuation in the key, a
// "vws-" key, or a value over 63 bytes) goes into one JSON object split across
// labels vws-tags-00, vws-tags-01, ... in order. JSON never holds a control
// character, so each chunk is a valid label value.
const (
	labelTagChunk  = "vws-tags-"
	labelMax       = 64
	labelValueMax  = 63
	labelReserve   = 6 // internal labels any update may add
	tagChunkDigits = 2
)

func userTags(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := map[string]string{}
	var blob strings.Builder
	for i := 0; ; i++ {
		part, ok := labels[tagChunkKey(i)]
		if !ok {
			break
		}
		blob.WriteString(part)
	}
	for key, value := range labels {
		if key == labelNameTag {
			out[nameTag] = value
			continue
		}
		if strings.HasPrefix(key, labelPrefix) {
			continue
		}
		out[key] = value
	}
	if blob.Len() > 0 {
		var packed map[string]string
		if err := json.Unmarshal([]byte(blob.String()), &packed); err == nil {
			maps.Copy(out, packed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func tagChunkKey(i int) string {
	return fmt.Sprintf("%s%0*d", labelTagChunk, tagChunkDigits, i)
}

// withInternalLabels returns extra plus the encoded tags. It fails only when
// the tags cannot fit in the labels compute allows.
func withInternalLabels(tags map[string]string, extra map[string]string) (map[string]string, error) {
	out := map[string]string{}
	maps.Copy(out, extra)
	packed := map[string]string{}
	for key, value := range tags {
		if labelOK(key, value) {
			out[key] = value
			continue
		}
		packed[key] = value
	}
	if len(packed) > 0 {
		raw, err := json.Marshal(packed)
		if err != nil {
			return nil, resource.Internal(err)
		}
		chunks := splitUTF8(string(raw), labelValueMax)
		if len(chunks) >= 100 {
			return nil, tagCapacityErr()
		}
		for i, c := range chunks {
			out[tagChunkKey(i)] = c
		}
	}
	reserve := labelReserve
	if len(extra) > reserve {
		reserve = len(extra)
	}
	if len(out)-len(extra)+reserve > labelMax {
		return nil, tagCapacityErr()
	}
	return out, nil
}

func tagCapacityErr() error {
	return resource.Invalid("TagSpecification", "tags exceed what the compute backend can store (64 labels of 63 bytes)")
}

// splitUTF8 cuts s into pieces of at most n bytes without splitting a rune.
func splitUTF8(s string, n int) []string {
	var out []string
	for len(s) > n {
		cut := n
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	return append(out, s)
}
