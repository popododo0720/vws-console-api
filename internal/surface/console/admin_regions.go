package console

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	PVEAPIURL      *string       `json:"pveApiUrl"`
	CAPEM          *string       `json:"caPem"`
	TokenID        *string       `json:"tokenId"`
	TokenSecret    *string       `json:"tokenSecret"`
	RegionEndpoint *string       `json:"regionEndpoint"`
	Zones          *[]store.Zone `json:"zones"`
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
	names, err := h.svc.RegionNames(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []string `json:"items"`
	}{Items: names})
}

func (h *handler) adminWriteRegion(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
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
		if match != "" && match != strconv.Quote(strconv.FormatInt(int64(v.Version), 10)) {
			adminError(w, r, store.ErrConflict)
			return
		}
	}
	if r.Method == http.MethodDelete {
		err := h.registry.Regions().Delete(r.Context(), v.Name, v.Version)
		if err == nil {
			err = h.registry.ReleaseCluster(r.Context(), v.ClusterName, v.Name)
		}
		if err != nil {
			adminError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
	oldCluster := v.ClusterName
	if in.Name != nil && r.Method == http.MethodPatch && *in.Name != v.Name {
		writeErr(w, r, resource.Invalid("name", "must match path"))
		return
	}
	for _, field := range []struct{ from, to *string }{
		{in.Name, &v.Name},
		{in.ClusterName, &v.ClusterName},
		{in.PVEAPIURL, &v.PVEAPIURL},
		{in.CAPEM, &v.CAPEM},
		{in.TokenID, &v.TokenID},
		{in.RegionEndpoint, &v.RegionEndpoint},
	} {
		if field.from != nil {
			*field.to = *field.from
		}
	}
	if in.Zones != nil {
		v.Zones = *in.Zones
	}
	if err := validateRegion(v, in.TokenSecret, r.Method == http.MethodPost); err != nil {
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
	claimed := oldCluster != v.ClusterName
	if claimed {
		if err := h.registry.ClaimCluster(r.Context(), v.ClusterName, v.Name); err != nil {
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
	pushErr := h.pushRegion(r.Context(), v, in.TokenSecret)
	v.LastError = nil
	if pushErr != nil {
		v.LastError = &resource.RegionStatusError{Time: h.now().UTC(), Message: "region registration push failed"}
	}
	v, err = h.registry.Regions().Update(r.Context(), v)
	if err != nil {
		adminError(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	if e := resource.AsError(pushErr); pushErr != nil && e.Code == resource.CodeInvalidArgument && e.Field == "token" {
		writeErr(w, r, resource.Invalid("tokenSecret", "resubmit token for an unregistered or invalid region credential"))
		return
	}
	writeJSON(w, status, v)
}

func (h *handler) pushRegion(ctx context.Context, v store.Region, token *string) error {
	data, err := json.Marshal(struct {
		Region string `json:"region"`
		//nolint:tagliatelle // The daemon registration protocol names cluster_name.
		ClusterName string       `json:"cluster_name"`
		TokenID     string       `json:"tokenId"`
		Token       *string      `json:"token,omitempty"`
		Zones       []store.Zone `json:"zones"`
	}{v.Name, v.ClusterName, v.TokenID, token, v.Zones})
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

func validateRegion(v store.Region, token *string, create bool) error {
	if !validRegionName(v.Name) {
		return resource.Invalid("name", "invalid Proxmox region name")
	}
	cluster := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	if !cluster.MatchString(v.ClusterName) {
		return resource.Invalid("clusterName", "invalid cluster name")
	}
	for _, field := range []struct{ name, value string }{
		{"pveApiUrl", v.PVEAPIURL}, {"regionEndpoint", v.RegionEndpoint},
	} {
		u, err := url.Parse(field.value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return resource.Invalid(field.name, "expected an HTTPS origin")
		}
	}
	if v.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(v.CAPEM)) {
		return resource.Invalid("caPem", "expected PEM certificates")
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
