package console

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type regionInput struct {
	Name           *string       `json:"name"`
	ClusterName    *string       `json:"clusterName"`
	PVEAPIURLs     *[]string     `json:"pveApiUrls"`
	CAPEM          *string       `json:"caPem"`
	TokenID        *string       `json:"tokenId"`
	TokenSecret    *string       `json:"tokenSecret"`
	RegionEndpoint *string       `json:"regionEndpoint"`
	Zones          *[]store.Zone `json:"zones"`

	FirewallTokenID     *string `json:"firewallTokenId"`
	FirewallTokenSecret *string `json:"firewallTokenSecret"`
	BackupTokenID       *string `json:"backupTokenId"`
	BackupTokenSecret   *string `json:"backupTokenSecret"`
}

func (h *handler) listRegions(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, r, resource.Invalid("query", "query parameters are not supported"))
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	items, err := h.svc.Regions(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []resource.RegionSummary `json:"items"`
	}{Items: items})
}

func (h *handler) regionCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, r, resource.Invalid("query", "query parameters are not supported"))
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	doc, err := h.svc.RegionCapabilities(r.Context(), c, r.PathValue("region"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (h *handler) adminWriteRegion(w http.ResponseWriter, r *http.Request) {
	// Only DELETE takes a query, force=true, and checks it itself.
	if r.Method != http.MethodDelete && !h.adminReady(w, r) || r.Method == http.MethodDelete && !h.adminRegistry(w, r) {
		return
	}
	if h.adminKey == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin writes require credentials.kek_file"})
		return
	}
	var v store.Region
	if r.Method != http.MethodPost {
		name := r.PathValue("name")
		if !validRegionName(name) {
			writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
			return
		}
		match := r.Header.Get("If-Match")
		if match == "" && r.Method == http.MethodPatch {
			writeErr(w, r, resource.Invalid("If-Match", "required"))
			return
		}
		var err error
		v, err = h.registry.Regions().Get(r.Context(), name)
		if err != nil {
			adminError(w, r, err)
			return
		}
		setAuditAccount(w, name)
		if v.Deleting && r.Method != http.MethodDelete {
			adminError(w, r, store.ErrRegionDeleting)
			return
		}
		if match != "" && match != strconv.Quote(strconv.FormatInt(int64(v.Version), 10)) {
			adminError(w, r, store.ErrConflict)
			return
		}
	}
	if r.Method == http.MethodDelete {
		force, err := deleteForce(r)
		if err == nil {
			err = h.deleteRegion(r.Context(), v, force)
		}
		var refusal *resource.Error
		switch {
		case errors.As(err, &refusal):
			writeErr(w, r, err)
		case err != nil:
			adminError(w, r, err)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	var in *regionInput
	if err := decode(w, r, &in); err != nil {
		writeErr(w, r, err)
		return
	}
	if in == nil {
		writeErr(w, r, resource.Invalid("body", "expected one JSON object"))
		return
	}
	oldCluster, oldEndpoint := v.ClusterName, v.RegionEndpoint
	if in.Name != nil && r.Method == http.MethodPatch && *in.Name != v.Name {
		writeErr(w, r, resource.Invalid("name", "must match path"))
		return
	}
	for _, field := range []struct{ from, to *string }{
		{in.Name, &v.Name},
		{in.ClusterName, &v.ClusterName},
		{in.CAPEM, &v.CAPEM},
		{in.TokenID, &v.TokenID},
		{in.RegionEndpoint, &v.RegionEndpoint},
		{in.FirewallTokenID, &v.FirewallTokenID},
		{in.BackupTokenID, &v.BackupTokenID},
	} {
		if field.from != nil {
			*field.to = *field.from
		}
	}
	if in.PVEAPIURLs != nil {
		v.PVEAPIURLs = *in.PVEAPIURLs
	}
	if in.Zones != nil {
		v.Zones = *in.Zones
	}
	if err := validateRegion(v, in.TokenSecret, r.Method == http.MethodPost); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := validateExtraTokens(v, in); err != nil {
		writeErr(w, r, err)
		return
	}
	if r.Method == http.MethodPatch && regionOrigin(v.RegionEndpoint) != regionOrigin(oldEndpoint) {
		if err := checkMove(v, in); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	setAuditAccount(w, v.Name)
	if r.Method == http.MethodPost {
		if _, err := h.registry.Regions().Get(r.Context(), v.Name); err == nil {
			writeErr(w, r, resource.Invalid("name", "already registered"))
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			adminError(w, r, err)
			return
		}
	}
	if in.TokenSecret != nil {
		v.TokenSecret = store.DescribeSecret(*in.TokenSecret)
	}
	if in.FirewallTokenSecret != nil {
		v.FirewallTokenSecret = store.DescribeSecret(*in.FirewallTokenSecret)
	}
	if v.FirewallTokenID == "" {
		v.FirewallTokenSecret = store.SecretMetadata{}
	}
	if in.BackupTokenSecret != nil {
		v.BackupTokenSecret = store.DescribeSecret(*in.BackupTokenSecret)
	}
	if v.BackupTokenID == "" {
		v.BackupTokenSecret = store.SecretMetadata{}
	}
	claimed := oldCluster != v.ClusterName
	if claimed {
		if err := h.registry.ClaimCluster(r.Context(), v.ClusterName, v.Name, h.now()); err != nil {
			if errors.Is(err, store.ErrExists) {
				writeErr(w, r, resource.Invalid("clusterName", "already registered"))
			} else {
				adminError(w, r, err)
			}
			return
		}
	}
	var err error
	status := http.StatusOK
	if r.Method == http.MethodPost {
		v, err = h.registry.Regions().Create(r.Context(), v)
		status = http.StatusCreated
	} else {
		v, err = h.registry.Regions().Update(r.Context(), v)
	}
	if err != nil {
		if claimed {
			err = errors.Join(err, h.registry.ReleaseCluster(r.Context(), v.ClusterName, v.Name))
		}
		if errors.Is(err, store.ErrExists) {
			writeErr(w, r, resource.Invalid("name", "already registered"))
		} else {
			adminError(w, r, err)
		}
		return
	}
	if claimed && oldCluster != "" {
		if err := h.registry.ReleaseCluster(r.Context(), oldCluster, v.Name); err != nil {
			adminError(w, r, err)
			return
		}
	}
	pushErr := h.pushRegion(r.Context(), v, in)
	v.LastError = nil
	if pushErr == nil && in.TokenSecret != nil {
		v.AckedTokenFingerprint = v.TokenSecret.Fingerprint
	}
	if pushErr != nil {
		message := resource.RegistrationFailureMessage(pushErr)
		if message == "" {
			message = "region registration push failed"
		}
		v.LastError = &resource.RegionStatusError{Time: h.now().UTC(), Message: message}
	}
	v, err = h.registry.Regions().Update(r.Context(), v)
	if err != nil {
		adminError(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	if e := resource.AsError(pushErr); pushErr != nil && e.Code == resource.CodeInvalidArgument {
		switch e.Field {
		case "token":
			writeErr(w, r, resource.Invalid("tokenSecret", "resubmit token for an unregistered or invalid region credential"))
			return
		case "firewallToken":
			writeErr(w, r, resource.Invalid("firewallTokenSecret", "resubmit the firewall token for a new credential"))
			return
		case "backupToken":
			writeErr(w, r, resource.Invalid("backupTokenSecret", "resubmit the backup token for a new credential"))
			return
		}
	}
	writeJSON(w, status, v)
}

// deleteForce reads the only query parameter of DELETE. force=true removes the
// registry entry even when the daemon cannot be told.
func deleteForce(r *http.Request) (bool, error) {
	// URL.Query drops a malformed pair, so "force=true&%zz" would read as force=true.
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false, resource.Invalid("query", "only force=true is supported")
	}
	if len(q) == 0 {
		return false, nil
	}
	if len(q) != 1 || len(q["force"]) != 1 || q.Get("force") != "true" {
		return false, resource.Invalid("query", "only force=true is supported")
	}
	return true, nil
}

// deleteRegion removes a region.
//
//  1. Mark: one registry transaction sets Deleting only while the record is at
//     the version read and the region has no project pool mappings, the guard
//     the registry delete uses. A mapped region is refused (409) and never
//     marked. The version the mark writes is the removal generation, higher
//     than any pushed registration. A call that finds the record already
//     Deleting joins and reuses that generation.
//  2. A marked region refuses PATCH and new project mappings, so it stays
//     unmapped, and no attempt ever clears the mark.
//  3. Deregister: the daemon removes the registration and refuses older
//     generations; repeating the same generation succeeds. Any failure leaves
//     the mark, and the delete is repeated until the daemon confirms.
//  4. Delete the entry at the marked version and release its cluster claim
//     in one transaction.
//
// force deletes the entry even when the daemon cannot be told; its PVE token
// is then deleted by hand.
func (h *handler) deleteRegion(ctx context.Context, v store.Region, force bool) error {
	if !v.Deleting {
		marked, err := h.registry.MarkRegionDeleting(ctx, v)
		if err != nil {
			return err
		}
		v = marked
	}
	var forced string
	if err := h.deregisterRegion(ctx, v); err != nil {
		forced = h.regionFailure(ctx, err)
		if !force {
			return &resource.Error{Code: resource.CodeUnavailable, Message: "region deregistration failed: " + forced +
				"; the region stays marked for deletion: repeat the delete, " +
				"or delete with force=true and delete the PVE token by hand"}
		}
	}
	// The cluster claim goes in the same transaction: a failed delete keeps
	// both, so the repeated delete releases the claim with the entry.
	if err := h.registry.DeleteRegion(ctx, v); err != nil {
		return err
	}
	// Only a committed delete is reported as one.
	if forced != "" {
		h.log.WarnContext(ctx, "region deleted without deregistering its daemon; delete its PVE token by hand",
			slog.String("region", v.Name), slog.String("reason", forced))
	}
	return nil
}

func (h *handler) deregisterRegion(ctx context.Context, v store.Region) error {
	if h.regionDeregistration == nil {
		return errors.New("region deregistration transport unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return h.regionDeregistration(ctx, v.RegionEndpoint, v.Name, int64(v.Version))
}

func (h *handler) pushRegion(ctx context.Context, v store.Region, in *regionInput) error {
	data, err := json.Marshal(struct {
		Region string `json:"region"`
		// Generation is the registry version of this registration; the daemon
		// refuses it once it has accepted a newer one or a removal.
		Generation int64 `json:"generation"`
		//nolint:tagliatelle // The daemon registration protocol names cluster_name.
		ClusterName     string       `json:"cluster_name"`
		PVEAPIURLs      []string     `json:"pveApiUrls"`
		CAPEM           string       `json:"caPem"`
		TokenID         string       `json:"tokenId"`
		Token           *string      `json:"token,omitempty"`
		Zones           []store.Zone `json:"zones"`
		FirewallTokenID string       `json:"firewallTokenId,omitempty"`
		FirewallToken   *string      `json:"firewallToken,omitempty"`
		BackupTokenID   string       `json:"backupTokenId,omitempty"`
		BackupToken     *string      `json:"backupToken,omitempty"`
	}{
		Region: v.Name, Generation: int64(v.Version), ClusterName: v.ClusterName, PVEAPIURLs: v.PVEAPIURLs, CAPEM: v.CAPEM,
		TokenID: v.TokenID, Token: in.TokenSecret,
		Zones: v.Zones, FirewallTokenID: v.FirewallTokenID, FirewallToken: in.FirewallTokenSecret,
		BackupTokenID: v.BackupTokenID, BackupToken: in.BackupTokenSecret,
	})
	if err != nil {
		return fmt.Errorf("encode registration: %w", err)
	}
	if h.regionRegistration == nil {
		return errors.New("region registration transport unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return h.regionRegistration(ctx, v.RegionEndpoint, data)
}

// regionOrigin is the origin the region client dials: the path, a trailing
// slash and the default port do not change the daemon.
func regionOrigin(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// checkMove refuses a move to another daemon unless it carries a new token.
// The old daemon keeps the credentials it holds, so it must never be able to
// use the new token, and the old token is revoked in PVE. The new token is
// compared with the one the old daemon acknowledged, and a move is refused
// while no token is acknowledged. The new daemon's first registration needs
// every configured secret.
func checkMove(v store.Region, in *regionInput) error {
	switch {
	case v.AckedTokenFingerprint == "":
		return resource.Invalid("regionEndpoint", "the daemon has not acknowledged a token; "+
			"resubmit tokenSecret at the current regionEndpoint before moving")
	case in.TokenSecret == nil:
		return resource.Invalid("tokenSecret", "required when regionEndpoint changes")
	case store.DescribeSecret(*in.TokenSecret).Fingerprint == v.AckedTokenFingerprint:
		return resource.Invalid("tokenSecret", "a move to another regionEndpoint needs a new token; "+
			"revoke the old token in PVE")
	case v.FirewallTokenID != "" && in.FirewallTokenSecret == nil:
		return resource.Invalid("firewallTokenSecret", "required when regionEndpoint changes")
	case v.BackupTokenID != "" && in.BackupTokenSecret == nil:
		return resource.Invalid("backupTokenSecret", "required when regionEndpoint changes")
	}
	return nil
}

func validRegionName(name string) bool {
	return len(name) <= 63 && regexp.MustCompile(`^pve-[a-z0-9]+(-[a-z0-9]+)*-[0-9]+$`).MatchString(name)
}

// validateExtraTokens checks the optional write tokens; the daemon refuses a
// new token id without its secret.
func validateExtraTokens(v store.Region, in *regionInput) error {
	tokenID := regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`)
	for _, token := range []struct {
		field, id string
		secret    *string
	}{
		{"firewallToken", v.FirewallTokenID, in.FirewallTokenSecret},
		{"backupToken", v.BackupTokenID, in.BackupTokenSecret},
	} {
		if token.id != "" && (!tokenID.MatchString(token.id) || token.id == v.TokenID) {
			return resource.Invalid(token.field+"Id", "expected a separate user@realm!token")
		}
		if token.secret != nil &&
			(token.id == "" || !regexp.MustCompile(`^[A-Za-z0-9._-]{1,512}$`).MatchString(*token.secret)) {
			return resource.Invalid(token.field+"Secret", "expected 1-512 token characters with a "+token.field+"Id")
		}
	}
	if v.BackupTokenID != "" && v.BackupTokenID == v.FirewallTokenID {
		return resource.Invalid("backupTokenId", "must differ from firewallTokenId")
	}
	return nil
}

func validateRegion(v store.Region, token *string, create bool) error {
	if !validRegionName(v.Name) {
		return resource.Invalid("name", "invalid Proxmox region name")
	}
	cluster := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	if !cluster.MatchString(v.ClusterName) {
		return resource.Invalid("clusterName", "invalid cluster name")
	}
	if err := resource.CheckPVEAPIURLs(v.PVEAPIURLs); err != nil {
		return err
	}
	u, err := url.Parse(v.RegionEndpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return resource.Invalid("regionEndpoint", "expected an HTTPS origin")
	}
	if !x509.NewCertPool().AppendCertsFromPEM([]byte(v.CAPEM)) {
		return resource.Invalid("caPem", "expected the PEM certificates that sign the PVE nodes")
	}
	tokenID := regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,32}![A-Za-z][A-Za-z0-9._-]{0,63}$`)
	if !tokenID.MatchString(v.TokenID) {
		return resource.Invalid("tokenId", "expected user@realm!token")
	}
	if create && token == nil || token != nil && !regexp.MustCompile(`^[A-Za-z0-9._-]{1,512}$`).MatchString(*token) {
		return resource.Invalid("tokenSecret", "expected 1-512 token characters")
	}
	letters, nodes := map[string]bool{}, map[string]bool{}
	if len(v.Zones) > 26 {
		return resource.Invalid("zones", "at most 26 zones")
	}
	for _, z := range v.Zones {
		if len(z.Letter) != 1 || z.Letter < "a" || z.Letter > "z" || letters[z.Letter] || len(z.Nodes) > 256 {
			return resource.Invalid("zones", "invalid or repeated letter")
		}
		letters[z.Letter] = true
		for _, node := range z.Nodes {
			if !cluster.MatchString(node) || nodes[node] {
				return resource.Invalid("zones", "invalid or repeated node")
			}
			nodes[node] = true
		}
	}
	return nil
}
