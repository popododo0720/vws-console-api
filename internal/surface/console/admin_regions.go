package console

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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
	old := v
	oldCluster := v.ClusterName
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
	if r.Method == http.MethodPatch && v.RegionEndpoint != old.RegionEndpoint {
		if err := h.leaveOldEndpoint(r.Context(), old, v); err != nil {
			writeErr(w, r, err)
			return
		}
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

// leaveOldEndpoint deregisters the daemon at the old endpoint before a PATCH
// that moves the region writes the registry or pushes to the new endpoint, so
// the registration and its token are never sent where the old daemon would
// keep serving them. The generation is the version of the record the PATCH
// read: every push is followed by a registry write, so it is above every
// generation the old daemon accepted. If the old daemon cannot be told, the
// PATCH is refused (400) unless it brings a new token: the old daemon then
// keeps only the old token, which the operator revokes in PVE.
func (h *handler) leaveOldEndpoint(ctx context.Context, old, v store.Region) error {
	err := h.deregisterRegion(ctx, old)
	if err == nil {
		return nil
	}
	reason := h.regionFailure(ctx, err)
	if v.TokenSecret.Fingerprint == old.TokenSecret.Fingerprint {
		return resource.Invalid("regionEndpoint", "the daemon at the old endpoint could not be deregistered ("+reason+
			"); make it reachable, or submit a new tokenSecret and revoke the old token in PVE")
	}
	h.log.WarnContext(ctx, "region endpoint changed without deregistering the old daemon; "+
		"it still holds the old tokens: revoke them in PVE",
		slog.String("region", old.Name), slog.String("reason", reason))
	return nil
}

// deleteForce reads the only query parameter of DELETE. force=true removes the
// registry entry even when the daemon cannot be told.
func deleteForce(r *http.Request) (bool, error) {
	q := r.URL.Query()
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
//  4. Delete the entry at the marked version, then release the cluster claim.
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
	if err := h.deregisterRegion(ctx, v); err != nil {
		reason := h.regionFailure(ctx, err)
		if !force {
			return &resource.Error{Code: resource.CodeUnavailable, Message: "region deregistration failed: " + reason +
				"; the region stays marked for deletion: repeat the delete, " +
				"or delete with force=true and delete the PVE token by hand"}
		}
		h.log.WarnContext(ctx, "region deleted without deregistering its daemon; delete its PVE token by hand",
			slog.String("region", v.Name), slog.String("reason", reason))
	}
	if err := h.registry.Regions().Delete(ctx, v.Name, v.Version); err != nil {
		return err
	}
	return h.registry.ReleaseCluster(ctx, v.ClusterName, v.Name)
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
