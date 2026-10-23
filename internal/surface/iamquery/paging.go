package iamquery

import (
	"regexp"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// defaultMaxItems is the AWS default page size of the IAM List actions.
const defaultMaxItems = 100

// pathPrefixRE is the AWS PathPrefix pattern, \u002F[\u0021-\u007F]*.
var pathPrefixRE = regexp.MustCompile(`^/[\x21-\x7F]*$`)

// pageParams reads Marker and MaxItems for a name-sorted listing. A Marker
// that is present must be 1 or more characters from U+0020 to U+00FF;
// MaxItems is 1 to 1000 and defaults to 100.
func pageParams(c *exchange) (string, int, error) {
	if err := mfaDeviceMarkerParam(c); err != nil {
		return "", 0, err
	}
	n, err := maxItemsParam(c)
	if err != nil {
		return "", 0, err
	}
	if n == 0 {
		n = defaultMaxItems
	}
	return c.form("Marker"), n, nil
}

// pathPrefixParam reads PathPrefix: 1 to 512 characters, a slash followed by
// U+0021 to U+007F. Omitted means every path.
func pathPrefixParam(c *exchange) (string, error) {
	p := c.form("PathPrefix")
	if !c.r.Form.Has("PathPrefix") {
		return "", nil
	}
	if len(p) > 512 || !pathPrefixRE.MatchString(p) {
		return "", resource.Invalid("pathPrefix", "1 validation error detected: Value '"+p+
			"' at 'pathPrefix' failed to satisfy constraint: "+
			`Member must satisfy regular expression pattern: \u002F[\u0021-\u007F]*`)
	}
	return p, nil
}

// pageByName returns the items after marker, at most maxItems of them, and,
// when more remain, the Marker of the next page: the last returned name. items
// must be sorted by name. As in AWS the Marker is opaque to the caller; one
// that names no item still resumes after it.
func pageByName[T any](items []T, name func(T) string, marker string, maxItems int) ([]T, bool, string) {
	start := 0
	if marker != "" {
		start = len(items)
		for i, it := range items {
			if name(it) > marker {
				start = i
				break
			}
		}
	}
	rest := items[start:]
	if len(rest) <= maxItems {
		return rest, false, ""
	}
	page := rest[:maxItems]
	return page, true, name(page[len(page)-1])
}
