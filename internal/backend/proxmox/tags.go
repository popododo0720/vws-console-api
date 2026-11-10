// Package proxmox is the Proxmox VE backend.
package proxmox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

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
// tags VWS keeps for itself (every other "vws." tag, any case), as stored.
// Other holds the rest as stored: operator tags and "vws.t." tags that do not
// decode. A writer keeps System and Other.
type Tags struct {
	User   map[string]string
	System []string
	Other  []string
}

func reservedKey(key string) bool {
	k := strings.ToLower(key)
	return strings.HasPrefix(k, "aws:") || strings.HasPrefix(k, "vws:") || strings.HasPrefix(k, "vws.")
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

// EncodeTag returns the Proxmox tag for an AWS tag. An empty key, a key
// starting with "aws:", "vws:" or "vws.", and text that is not UTF-8 are
// InvalidParameterValue.
func EncodeTag(key, value string) (string, error) {
	switch {
	case key == "":
		return "", resource.Invalid("tags", "a tag key must not be empty")
	case reservedKey(key):
		return "", resource.Invalid("tags", "tag keys starting with 'aws:', 'vws:' or 'vws.' are reserved")
	case !utf8.ValidString(key) || !utf8.ValidString(value):
		return "", resource.Invalid("tags", "tag keys and values must be UTF-8")
	}
	var b strings.Builder
	b.WriteString(userTagPrefix)
	encodeComponent(&b, key)
	b.WriteByte('.')
	encodeComponent(&b, value)
	return b.String(), nil
}

// DecodeTag returns the AWS tag a Proxmox tag encodes. ok is false for any
// other tag, system tags included, and for every spelling EncodeTag would not
// write (such as "_61" for "a", or a reserved key): only then is each key one
// tag.
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
	if !okKey || !okValue {
		return "", "", false
	}
	if canonical, err := EncodeTag(key, value); err != nil || canonical != tag {
		return "", "", false
	}
	return key, value, true
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
// takes the Proxmox tag's value; a key in two Proxmox tags takes the smaller
// tag. It fails only when the block does not parse; a caller listing many
// objects skips that one rather than failing the listing.
func ReadTags(pveTags []string, description string) (Tags, error) {
	user, err := descriptionTags(description)
	if err != nil {
		return Tags{}, err
	}
	var out Tags
	inline := map[string]string{}
	for _, t := range pveTags {
		lower := strings.ToLower(t)
		if k, v, ok := DecodeTag(t); ok {
			if prev, dup := inline[k]; !dup || t < prev {
				inline[k] = t
				user[k] = v
			}
		} else if strings.HasPrefix(lower, "vws.") && !strings.HasPrefix(lower, userTagPrefix) {
			out.System = append(out.System, t)
		} else {
			out.Other = append(out.Other, t)
		}
	}
	out.User = user
	return out, nil
}

// descriptionBlock returns the JSON of a "vws:tags {...}" line. Any other
// line, "vws:tags null" included, is the operator's text.
func descriptionBlock(line string) (string, bool) {
	block, found := strings.CutPrefix(strings.TrimSuffix(line, "\r"), descriptionPrefix)
	return block, found && strings.HasPrefix(block, "{")
}

// descriptionTags reads the block. Keys EncodeTag refuses (empty, reserved)
// are not user tags and are left out.
func descriptionTags(description string) (map[string]string, error) {
	tags := map[string]string{}
	found := false
	for line := range strings.SplitSeq(description, "\n") {
		block, ok := descriptionBlock(line)
		if !ok {
			continue
		}
		if found {
			return nil, fmt.Errorf("proxmox: the description has more than one %q block", descriptionPrefix)
		}
		found = true
		var stored map[string]string
		if err := json.Unmarshal([]byte(block), &stored); err != nil {
			return nil, fmt.Errorf("proxmox: read the vws:tags description block: %w", err)
		}
		for k, v := range stored {
			if _, err := EncodeTag(k, v); err == nil {
				tags[k] = v
			}
		}
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
