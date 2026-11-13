package proxmox

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	launchMarkerPrefix = "vws:v="
	// MaxDescriptionBytes bounds the whole description, including operator text
	// and vws:tags. A byte bound is conservative for PVE's character limit.
	MaxDescriptionBytes = 8192
)

// LaunchMarker is the per-VM recovery input for a clone. User data is a PVE
// snippet volume ID, never the body. Index is zero based; DOT contains the
// eight-hex drive serial prefixes whose volumes are deleted on termination.
type LaunchMarker struct {
	UUID        string
	Key         string
	Fingerprint string
	Index       int
	Count       int
	Image       resource.ImageID
	Account     resource.AccountID
	Type        string
	Subnet      resource.SubnetID
	KeyPair     string
	Snippet     string
	DOT         []string
	Attempt     int
	IPFence     string
	CreatedAt   int64
}

func (m LaunchMarker) line() (string, error) {
	if err := m.validate(); err != nil {
		return "", err
	}
	fields := []string{
		"vws:v=1", "uuid=" + m.UUID, "key=" + m.Key, "fp=" + m.Fingerprint,
		"n=" + strconv.Itoa(m.Index) + "/" + strconv.Itoa(m.Count),
		"ami=" + m.Image.String(), "acct=" + m.Account.String(),
		"type=" + url.QueryEscape(m.Type), "subnet=" + m.Subnet.String(),
		"kp=" + url.QueryEscape(m.KeyPair), "ud=" + url.QueryEscape(m.Snippet),
		"dot=" + strings.Join(m.DOT, ","), "attempt=" + strconv.Itoa(m.Attempt),
	}
	if m.IPFence != "" {
		fields = append(fields, "ipfence="+m.IPFence)
	}
	if m.CreatedAt != 0 {
		fields = append(fields, "created="+strconv.FormatInt(m.CreatedAt, 10))
	}
	return strings.Join(fields, " "), nil
}

func (m LaunchMarker) validate() error {
	if err := checkUUID(m.UUID); err != nil {
		return fmt.Errorf("proxmox: launch marker: %w", err)
	}
	if m.IPFence != "" && !launchHex(m.IPFence, 32) {
		return fmt.Errorf("%w: launch IP fence", ErrInput)
	}
	if m.CreatedAt < 0 || !launchHex(m.Key, 64) || !launchHex(m.Fingerprint, 64) ||
		m.Count < 1 || m.Count > 10 || m.Index < 0 || m.Index >= m.Count || m.Attempt < 1 {
		return fmt.Errorf("%w: launch marker identity or index", ErrInput)
	}
	if m.Image.IsZero() || m.Account.IsZero() || m.Subnet.IsZero() ||
		m.Type == "" || len(m.Type) > 64 || !utf8.ValidString(m.Type) ||
		len(m.KeyPair) > 255 || !utf8.ValidString(m.KeyPair) {
		return fmt.Errorf("%w: launch marker resource fields", ErrInput)
	}
	if m.Snippet != "" {
		storage, file, ok := strings.Cut(m.Snippet, ":snippets/")
		if !ok || storage == "" || len(m.Snippet) > 1024 || file == "" || file == "." || file == ".." ||
			path.Base(file) != file ||
			strings.Trim(storage, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" ||
			strings.Trim(file, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
			return fmt.Errorf("%w: launch marker snippet must be a storage:snippets/file volume ID", ErrInput)
		}
	}
	if len(m.DOT) > resource.MaxLaunchVolumes {
		return fmt.Errorf("%w: launch marker has too many disks", ErrInput)
	}
	seen := map[string]bool{}
	for _, serial := range m.DOT {
		if !launchHex(serial, 8) || seen[serial] {
			return fmt.Errorf("%w: launch marker disk serial", ErrInput)
		}
		seen[serial] = true
	}
	return nil
}

func launchHex(s string, size int) bool {
	return len(s) == size && strings.Trim(s, hexDigits) == ""
}

// WithLaunchMarker replaces one marker line or appends it. Operator text and
// tag blocks are preserved byte for byte. Ambiguous or oversized descriptions
// are refused before a caller can submit a PVE config write.
func WithLaunchMarker(description string, marker LaunchMarker) (string, error) {
	line, err := marker.line()
	if err != nil {
		return "", err
	}
	if _, _, err := ReadLaunchMarker(description); err != nil {
		return "", err
	}
	lines := strings.Split(description, "\n")
	found := false
	for i, old := range lines {
		if strings.HasPrefix(old, launchMarkerPrefix) {
			lines[i], found = line, true
		}
	}
	out := strings.Join(lines, "\n")
	if !found {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += line
	}
	if len(out) > MaxDescriptionBytes {
		return "", fmt.Errorf("%w: launch description exceeds %d bytes", ErrInput, MaxDescriptionBytes)
	}
	return out, nil
}

// ReadLaunchMarker reads the sole version-1 marker, even after clone unlock.
// Malformed, duplicate and unknown-version markers are errors, never absence.
func ReadLaunchMarker(description string) (LaunchMarker, bool, error) {
	var marker LaunchMarker
	found := false
	if len(description) > MaxDescriptionBytes {
		return marker, false, fmt.Errorf("%w: launch description exceeds %d bytes", ErrInput, MaxDescriptionBytes)
	}
	for line := range strings.SplitSeq(description, "\n") {
		if !strings.HasPrefix(line, launchMarkerPrefix) {
			continue
		}
		if found {
			return LaunchMarker{}, false, fmt.Errorf("%w: duplicate launch marker", ErrInput)
		}
		var err error
		marker, err = parseLaunchMarker(line)
		if err != nil {
			return LaunchMarker{}, false, err
		}
		found = true
	}
	return marker, found, nil
}

func parseLaunchMarker(line string) (LaunchMarker, error) {
	fields := strings.Split(line, " ")
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		k, v, ok := strings.Cut(field, "=")
		if _, duplicate := values[k]; !ok || duplicate {
			return LaunchMarker{}, fmt.Errorf("%w: ambiguous launch marker field", ErrInput)
		}
		values[k] = v
	}
	var m LaunchMarker
	i, n, _ := strings.Cut(values["n"], "/")
	var errs []error
	var err error
	m.Index, err = strconv.Atoi(i)
	errs = append(errs, err)
	m.Count, err = strconv.Atoi(n)
	errs = append(errs, err)
	m.Attempt, err = strconv.Atoi(values["attempt"])
	errs = append(errs, err)
	m.Image, err = resource.Parse[resource.ImageID](values["ami"])
	errs = append(errs, err)
	m.Account, err = resource.Parse[resource.AccountID](values["acct"])
	errs = append(errs, err)
	m.Subnet, err = resource.Parse[resource.SubnetID](values["subnet"])
	errs = append(errs, err)
	m.Type, err = url.QueryUnescape(values["type"])
	errs = append(errs, err)
	m.KeyPair, err = url.QueryUnescape(values["kp"])
	errs = append(errs, err)
	m.Snippet, err = url.QueryUnescape(values["ud"])
	errs = append(errs, err)
	if created, exists := values["created"]; exists {
		m.CreatedAt, err = strconv.ParseInt(created, 10, 64)
		errs = append(errs, err)
	}
	for _, err := range errs {
		if err != nil {
			return LaunchMarker{}, fmt.Errorf("%w: invalid launch marker field", ErrInput)
		}
	}
	m.UUID, m.Key, m.Fingerprint = values["uuid"], values["key"], values["fp"]
	m.IPFence = values["ipfence"]
	if values["dot"] != "" {
		m.DOT = strings.Split(values["dot"], ",")
	}
	canonical, err := m.line()
	if err != nil {
		return LaunchMarker{}, err
	}
	// Canonical equality also refuses missing, unknown or reordered fields,
	// alternate numeric spellings, unsupported versions and escaped aliases.
	if canonical != line {
		return LaunchMarker{}, fmt.Errorf("%w: noncanonical launch marker", ErrInput)
	}
	return m, nil
}

// LaunchMarkerTags returns the four launch replay tags set at finalization.
// These truncated hashes index inventory; they do not replace the full marker
// when a later recovery needs the full fingerprint or launch plan.
func LaunchMarkerTags(marker LaunchMarker, reservation resource.ReservationID) ([]string, error) {
	if err := marker.validate(); err != nil {
		return nil, err
	}
	local := strings.TrimPrefix(reservation.String(), "r-")
	if !validOperationLocal(local) {
		return nil, fmt.Errorf("%w: launch reservation", ErrInput)
	}
	return []string{
		"vws.k." + marker.Key[:24], "vws.f." + marker.Fingerprint[:16],
		"vws.n." + strconv.Itoa(marker.Index), "vws.r." + local,
	}, nil
}
