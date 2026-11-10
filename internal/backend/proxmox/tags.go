// Package proxmox is the Proxmox VE backend.
package proxmox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	userTagPrefix = "vws.t."
	// maxTagLen is the longest encoded tag kept in the VM's tags; a longer one
	// goes to the description block.
	maxTagLen         = 128
	descriptionPrefix = "vws:tags "
	hexDigits         = "0123456789abcdef"
)

// Tags are the tags of one Proxmox object. User holds the AWS tags from both
// the Proxmox tags and the description block, each key once. System holds the
// tags VWS keeps for itself, as stored.
type Tags struct {
	User   map[string]string
	System []string
}

func reservedKey(key string) bool {
	k := strings.ToLower(key)
	return strings.HasPrefix(k, "aws:") || strings.HasPrefix(k, "vws:") || strings.HasPrefix(k, "vws.")
}

func isSystemTag(tag string) bool {
	if tag == "vws.holder" {
		return true
	}
	for _, p := range []string{
		"vws.k.", "vws.f.", "vws.n.", "vws.r.", "vws.ami.", "vws.kp.", "vws.dot.", "vws.d.", "vws.vt.", "vws.live.",
	} {
		if strings.HasPrefix(tag, p) {
			return true
		}
	}
	return false
}

func encodeComponent(b *strings.Builder, s string) {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte('+')
			b.WriteByte(c - 'A' + 'a')
		default:
			b.WriteByte('_')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func decodeComponent(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		case c == '+':
			if i+1 >= len(s) || s[i+1] < 'a' || s[i+1] > 'z' {
				return "", false
			}
			i++
			b.WriteByte(s[i] - 'a' + 'A')
		case c == '_':
			if i+2 >= len(s) {
				return "", false
			}
			hi, okHi := hexValue(s[i+1])
			lo, okLo := hexValue(s[i+2])
			if !okHi || !okLo {
				return "", false
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		default:
			return "", false
		}
	}
	return b.String(), true
}

// EncodeTag returns the Proxmox tag for an AWS tag. A key starting with
// "aws:", "vws:" or "vws." is InvalidParameterValue.
func EncodeTag(key, value string) (string, error) {
	if reservedKey(key) {
		return "", resource.Invalid("tags", "tag keys starting with 'aws:', 'vws:' or 'vws.' are reserved")
	}
	var b strings.Builder
	b.WriteString(userTagPrefix)
	encodeComponent(&b, key)
	b.WriteByte('.')
	encodeComponent(&b, value)
	return b.String(), nil
}

// DecodeTag returns the AWS tag a Proxmox tag encodes. ok is false for any
// other tag, system tags included.
func DecodeTag(tag string) (key, value string, ok bool) {
	rest, found := strings.CutPrefix(tag, userTagPrefix)
	if !found {
		return "", "", false
	}
	k, v, found := strings.Cut(rest, ".")
	if !found {
		return "", "", false
	}
	key, okKey := decodeComponent(k)
	value, okValue := decodeComponent(v)
	return key, value, okKey && okValue
}

// Split divides AWS tags into the Proxmox tags to set, sorted, and the tags
// whose encoding exceeds 128 characters, which belong in the description block.
func Split(tags map[string]string) (pve []string, overflow map[string]string, err error) {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		tag, err := EncodeTag(k, tags[k])
		if err != nil {
			return nil, nil, err
		}
		if len(tag) <= maxTagLen {
			pve = append(pve, tag)
			continue
		}
		if overflow == nil {
			overflow = map[string]string{}
		}
		overflow[k] = tags[k]
	}
	return pve, overflow, nil
}

// ReadTags merges the Proxmox tags and the description block. A key in both
// takes the Proxmox tag's value.
func ReadTags(pveTags []string, description string) (Tags, error) {
	user, err := descriptionTags(description)
	if err != nil {
		return Tags{}, err
	}
	var out Tags
	for _, t := range pveTags {
		if k, v, ok := DecodeTag(t); ok {
			user[k] = v
		} else if isSystemTag(t) {
			out.System = append(out.System, t)
		}
	}
	out.User = user
	return out, nil
}

func descriptionTags(description string) (map[string]string, error) {
	tags := map[string]string{}
	for line := range strings.SplitSeq(description, "\n") {
		block, found := strings.CutPrefix(line, descriptionPrefix)
		if !found {
			continue
		}
		if err := json.Unmarshal([]byte(block), &tags); err != nil {
			return nil, fmt.Errorf("proxmox: read the vws:tags description block: %w", err)
		}
		break
	}
	return tags, nil
}

// WithDescriptionTags returns the description with its vws:tags block replaced
// by one holding tags, or removed when tags is empty. Other lines stay.
func WithDescriptionTags(description string, tags map[string]string) (string, error) {
	var kept []string
	for line := range strings.SplitSeq(description, "\n") {
		if !strings.HasPrefix(line, descriptionPrefix) {
			kept = append(kept, line)
		}
	}
	rest := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if len(tags) == 0 {
		return rest, nil
	}
	block, err := json.Marshal(tags)
	if err != nil {
		return "", fmt.Errorf("proxmox: write the vws:tags description block: %w", err)
	}
	if rest == "" {
		return descriptionPrefix + string(block), nil
	}
	return rest + "\n" + descriptionPrefix + string(block), nil
}
