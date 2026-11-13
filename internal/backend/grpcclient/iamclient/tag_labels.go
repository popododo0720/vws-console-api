package iamclient

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	labelPrefix  = "vws-"
	labelNameTag = "vws-name"
	nameTag      = "Name"
)

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

// userTags fails when the tag chunks do not decode, so a later CreateTags
// cannot rewrite the labels without the tags they hold (#93).
func userTags(labels map[string]string) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil //nolint:nilnil // no tags is a nil map, not an error
	}
	out := map[string]string{}
	var blob strings.Builder
	read := 0
	for ; ; read++ {
		part, ok := labels[tagChunkKey(read)]
		if !ok {
			break
		}
		blob.WriteString(part)
	}
	chunks := 0
	for key, value := range labels {
		if strings.HasPrefix(key, labelTagChunk) {
			chunks++
		}
		if key == labelNameTag {
			out[nameTag] = value
			continue
		}
		if strings.HasPrefix(key, labelPrefix) {
			continue
		}
		out[key] = value
	}
	if chunks != read {
		return nil, resource.Internal(fmt.Errorf("tag labels do not decode: %d of %d chunks are in sequence", read, chunks))
	}
	if blob.Len() > 0 {
		var packed map[string]string
		if err := json.Unmarshal([]byte(blob.String()), &packed); err != nil {
			return nil, resource.Internal(fmt.Errorf("tag labels do not decode: %w", err))
		}
		maps.Copy(out, packed)
	}
	if len(out) == 0 {
		return nil, nil //nolint:nilnil // no tags is a nil map, not an error
	}
	return out, nil
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

// tagCapacityErr is the answer for tags EC2 accepts that the labels cannot
// hold. EC2 allows 50 tags of 128 and 256 characters, up to 76 800 bytes of
// UTF-8, and the user tags get labelMax-labelReserve labels of 63 bytes, so
// no encoding holds every legal set (#398).
func tagCapacityErr() error {
	return resource.TagLimitExceeded("tags", fmt.Sprintf(
		"The tags exceed what VWS can store for one resource: a tag whose key is at most %d "+
			"lowercase letters, digits, '_' or '-', starting with a letter, and whose value is at "+
			"most %d bytes with no control character takes one label; the other tags are packed "+
			"as JSON into labels of at most %d bytes; all of them must fit in at most %d labels, "+
			"fewer while the resource holds more internal labels, such as detach records. "+
			"Shorten or remove tags of the second kind.",
		labelValueMax, labelValueMax, labelValueMax, labelMax-labelReserve))
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
