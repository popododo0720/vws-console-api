package resource

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// DefaultPBSPort is the port of a PBS repository that names none.
const DefaultPBSPort = "8007"

var (
	pbsHost      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)
	pbsDatastore = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{2,31}$`)
	pbsNamespace = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,30}$`)
	// PBSFingerprint is the SHA-256 of the PBS server certificate as PBS
	// prints it: 32 lowercase hex pairs joined by colons.
	pbsFingerprint = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){31}$`)
)

// PBSRepository is a parsed PBS repository: the address of the server and one datastore.
type PBSRepository struct {
	// Address is host:port, with an IPv6 host in brackets.
	Address   string
	Datastore string
}

// ParsePBSRepository reads host[:port]:datastore, the repository form of
// proxmox-backup-client without the user part; the token names the user.
func ParsePBSRepository(repository string) (PBSRepository, error) {
	invalid := Invalid("pbsRepository", "expected host[:port]:datastore")
	i := strings.LastIndexByte(repository, ':')
	if i <= 0 || !pbsDatastore.MatchString(repository[i+1:]) {
		return PBSRepository{}, invalid
	}
	server, port := repository[:i], DefaultPBSPort
	if host, p, err := net.SplitHostPort(server); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return PBSRepository{}, invalid
		}
		// SplitHostPort drops the brackets of an IPv6 host.
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		server, port = host, p
	}
	// An IPv6 host is in brackets, so the port and datastore separators stay unambiguous.
	if v6, ok := strings.CutPrefix(server, "["); ok {
		v6, ok = strings.CutSuffix(v6, "]")
		if ip := net.ParseIP(v6); !ok || ip == nil || ip.To4() != nil {
			return PBSRepository{}, invalid
		}
		server = v6
	} else if !pbsHost.MatchString(server) || strings.Contains(server, "..") {
		return PBSRepository{}, invalid
	}
	return PBSRepository{Address: net.JoinHostPort(server, port), Datastore: repository[i+1:]}, nil
}

// DRSettings are the cold-DR settings of one region: the PVE storage of the
// PBS, the repository and namespace that hold the backups, the PBS
// certificate fingerprint and the PBS token id. They are all set, or all
// empty for a region without DR.
type DRSettings struct {
	Storage, Repository, Namespace, Fingerprint, TokenID string
}

// Configured reports whether any setting is set.
func (d DRSettings) Configured() bool { return d != DRSettings{} }

// CheckDRSettings validates d: a PVE storage id, the repository, a namespace
// other than the root (1 to 7 levels), the server certificate fingerprint and
// a token id of the form user@realm!token, or nothing at all.
func CheckDRSettings(d DRSettings) error {
	if !d.Configured() {
		return nil
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9._-]{0,98}[a-z0-9]$`).MatchString(d.Storage) {
		return Invalid("drStorage", "expected the PVE storage id of the PBS")
	}
	if _, err := ParsePBSRepository(d.Repository); err != nil {
		return err
	}
	parts := strings.Split(d.Namespace, "/")
	if len(parts) > 7 {
		return Invalid("pbsNamespace", "expected 1 to 7 namespace levels")
	}
	for _, part := range parts {
		if !pbsNamespace.MatchString(part) {
			return Invalid("pbsNamespace", "expected 1 to 7 namespace levels")
		}
	}
	if !pbsFingerprint.MatchString(d.Fingerprint) {
		return Invalid("pbsFingerprint", "expected the SHA-256 fingerprint of the PBS certificate as lowercase hex pairs")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`).
		MatchString(d.TokenID) {
		return Invalid("pbsTokenId", "expected user@realm!token")
	}
	return nil
}
