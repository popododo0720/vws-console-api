package resource

import (
	"slices"
	"strings"
	"unicode"
)

// maxListKeys is the largest page ListObjectsV2 accepts.
const maxListKeys = 1000

// ObjectQuery lists the keys in one bucket.
// MaxKeys zero means the default, 1000. Token, when set, wins over StartAfter.
// Token is a position: the next page starts at the first rolled-up entry
// whose name is greater. A deleted key does not make the token unknown.
type ObjectQuery struct {
	Bucket     BucketName `json:"bucket"`
	Prefix     string     `json:"prefix,omitempty"`
	Delimiter  string     `json:"delimiter,omitempty"`
	MaxKeys    int        `json:"maxKeys"`
	Token      string     `json:"pageToken,omitempty"`
	StartAfter string     `json:"startAfter,omitempty"`
}

// Normalize checks the bucket and the listing fields.
func (q ObjectQuery) Normalize() (ObjectQuery, error) {
	if q.Bucket.IsZero() {
		return ObjectQuery{}, Invalid("bucket", "required")
	}
	if q.MaxKeys == 0 {
		q.MaxKeys = maxListKeys
	}
	if q.MaxKeys < 1 || q.MaxKeys > maxListKeys {
		return ObjectQuery{}, Invalid("maxKeys", "must be from 1 to 1000")
	}
	if err := listingField(q.Prefix, "prefix"); err != nil {
		return ObjectQuery{}, err
	}
	if err := listingField(q.Delimiter, "delimiter"); err != nil {
		return ObjectQuery{}, err
	}
	if err := listingField(q.Token, "pageToken"); err != nil {
		return ObjectQuery{}, err
	}
	if err := listingField(q.StartAfter, "startAfter"); err != nil {
		return ObjectQuery{}, err
	}
	return q, nil
}

func listingField(s, field string) error {
	if len(s) > 1024 {
		return Invalid(field, "malformed")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return Invalid(field, "malformed")
		}
	}
	return nil
}

// ObjectListing is one page of a bucket listing.
// Objects and CommonPrefixes together are at most MaxKeys entries, ordered by
// the key or the common prefix. NextToken is the last of those entries.
// The page is truncated exactly when NextToken is set.
type ObjectListing struct {
	Objects        []Object `json:"objects,omitempty"`
	CommonPrefixes []string `json:"commonPrefixes,omitempty"`
	NextToken      string   `json:"nextPageToken,omitempty"`
}

type listEntry struct {
	name string
	obj  *Object
}

// PageObjects rolls keys into one page.
// A delimiter collapses every key under a common prefix into that prefix, and
// those keys are not returned as objects. StartAfter drops raw keys up to and
// including that key, then the remainder is rolled up, so a cursor inside a
// group keeps the group when a later key still belongs to it. Token is applied
// after the rollup and wins over StartAfter. Keys from another bucket are ignored.
func PageObjects(keys []Object, q ObjectQuery) (ObjectListing, error) {
	q, err := q.Normalize()
	if err != nil {
		return ObjectListing{}, err
	}
	if q.Token == "" {
		keys = afterKey(keys, q.StartAfter)
	}
	entries := rollup(keys, q.Bucket, q.Prefix, q.Delimiter)
	start := 0
	if q.Token != "" {
		for start < len(entries) && entries[start].name <= q.Token {
			start++
		}
	}
	end := start + q.MaxKeys
	var next string
	if end < len(entries) {
		next = entries[end-1].name
	} else {
		end = len(entries)
	}
	out := ObjectListing{NextToken: next}
	for _, entry := range entries[start:end] {
		if entry.obj == nil {
			out.CommonPrefixes = append(out.CommonPrefixes, entry.name)
			continue
		}
		out.Objects = append(out.Objects, *entry.obj)
	}
	return out, nil
}

func afterKey(keys []Object, startAfter string) []Object {
	if startAfter == "" {
		return keys
	}
	out := make([]Object, 0, len(keys))
	for _, obj := range keys {
		if obj.Key.String() > startAfter {
			out = append(out, obj)
		}
	}
	return out
}

func rollup(keys []Object, bucket BucketName, prefix, delimiter string) []listEntry {
	sorted := append([]Object(nil), keys...)
	slices.SortFunc(sorted, func(a, b Object) int {
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	var entries []listEntry
	for i := range sorted {
		obj := sorted[i]
		key := obj.Key.String()
		if obj.Bucket != bucket || !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			if cut := strings.Index(rest, delimiter); cut >= 0 {
				common := prefix + rest[:cut+len(delimiter)]
				if len(entries) > 0 && entries[len(entries)-1].obj == nil && entries[len(entries)-1].name == common {
					continue
				}
				entries = append(entries, listEntry{name: common})
				continue
			}
		}
		copied := obj
		entries = append(entries, listEntry{name: key, obj: &copied})
	}
	return entries
}
