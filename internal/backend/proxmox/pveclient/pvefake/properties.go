package pvefake

import "strings"

// parseProperties resolves the drive file alias and named fields used by clone ACLs.
func parseProperties(value string) map[string]string {
	result := map[string]string{}
	for part := range strings.SplitSeq(value, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		key, value, named := strings.Cut(part, "=")
		if !named {
			key, value = "file", key
		}
		if key == "volume" {
			key = "file"
		}
		result[key] = value
	}
	return result
}
