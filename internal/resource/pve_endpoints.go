package resource

import (
	"net/url"
	"strings"
)

// MaxPVEAPIURLs bounds the PVE node addresses of one region.
const MaxPVEAPIURLs = 16

// CheckPVEAPIURLs validates the PVE node addresses of one region: 1 to
// MaxPVEAPIURLs distinct HTTPS origins without credentials, query or fragment.
func CheckPVEAPIURLs(urls []string) error {
	if len(urls) < 1 || len(urls) > MaxPVEAPIURLs {
		return Invalid("pveApiUrls", "expected 1 to 16 HTTPS origins")
	}
	seen := make(map[string]bool, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 255 || strings.ContainsAny(raw, "?#") || u.Scheme != "https" ||
			u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
			return Invalid("pveApiUrls", "each entry must be an HTTPS origin without credentials, query or fragment")
		}
		host := strings.ToLower(u.Host)
		if seen[host] {
			return Invalid("pveApiUrls", "duplicate entry")
		}
		seen[host] = true
	}
	return nil
}
