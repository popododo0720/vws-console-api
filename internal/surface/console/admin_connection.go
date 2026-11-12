package console

import (
	"context"
	"mime"
	"net/http"
	"regexp"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) adminTestAWSAccount(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		unsupportedMedia(w)
		return
	}
	if !h.adminReady(w, r) {
		return
	}
	if h.adminKey == nil || h.accountConnection == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "AWS connection test requires KEK and proxy"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var v store.AWSAccount
	var external string
	id := r.PathValue("id")
	if id != "" {
		if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(id) {
			writeErr(w, r, resource.Invalid("awsAccountId", "must be 12 digits"))
			return
		}
		var empty *struct{}
		if err := decode(w, r, &empty); err != nil || empty == nil {
			writeErr(w, r, resource.Invalid("body", "saved tests require an empty JSON object"))
			return
		}
		var err error
		v, err = h.registry.AWSAccounts().Get(ctx, id)
		if err != nil {
			adminError(w, r, err)
			return
		}
		plain, err := h.adminKey.Open(v.SealedExternalID, id)
		if err != nil {
			unusableSavedAccount(w)
			return
		}
		defer clear(plain)
		external = string(plain)
	} else {
		var in *accountInput
		if err := decode(w, r, &in); err != nil {
			if resource.CodeOf(err) != resource.CodePayloadTooLarge {
				err = resource.Invalid("body", "invalid AWS connection test body")
			}
			writeErr(w, r, err)
			return
		}
		if in == nil || in.ID == nil || in.RoleARN == nil || in.ExternalID == nil || in.AllowedRegions == nil {
			writeErr(w, r, resource.Invalid("body", "all AWS account fields are required"))
			return
		}
		v = store.AWSAccount{ID: *in.ID, RoleARN: *in.RoleARN, AllowedRegions: *in.AllowedRegions}
		external = *in.ExternalID
	}
	if err := validateAccount(v, &external, true); err != nil {
		if id != "" {
			unusableSavedAccount(w)
			return
		}
		writeErr(w, r, err)
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	steps := h.accountConnection(ctx, resource.AWSConnectionRequest{
		AccountID: v.ID, RoleARN: v.RoleARN, ExternalID: external,
	}, c.Principal)
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{steps})
}

func unusableSavedAccount(w http.ResponseWriter) {
	steps := resource.AWSConnectionSteps(false, false)
	steps[0].Message = "saved registration cannot be used; save it again"
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{steps})
}

func (h *handler) adminTestRegion(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	if h.adminKey == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin tests require credentials.kek_file"})
		return
	}
	var v store.Region
	name := r.PathValue("name")
	if name != "" {
		if !validRegionName(name) {
			writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
			return
		}
		var err error
		v, err = h.registry.Regions().Get(r.Context(), name)
		if err != nil {
			adminError(w, r, err)
			return
		}
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
	if name != "" {
		if in.Name != nil || in.ClusterName != nil || in.PVEAPIURL != nil || in.CAPEM != nil ||
			in.TokenID != nil || in.RegionEndpoint != nil || in.Zones != nil {
			writeErr(w, r, resource.Invalid("name", "saved tests accept only tokenSecret; use the unsaved test for edits"))
			return
		}
	} else {
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
	}
	if err := validateRegion(v, in.TokenSecret, name == ""); err != nil {
		writeErr(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	steps := make([]resource.ConnectionStep, 0, 5)
	if in.TokenSecret == nil {
		for _, step := range []string{"tls", "version", "cluster_name", "privileges"} {
			steps = append(steps, resource.ConnectionStep{
				Name: step, Result: resource.ConnectionSkipped, Message: "tokenSecret is needed; only the region daemon stores it",
			})
		}
	} else {
		if h.regionConnection == nil {
			writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "PVE connection test unavailable"})
			return
		}
		steps = h.regionConnection(ctx, v, *in.TokenSecret)
	}
	last := resource.ConnectionStep{Name: "regionapi", Result: resource.ConnectionSkipped, Message: "previous step failed"}
	failed := false
	for _, step := range steps {
		failed = failed || step.Result == resource.ConnectionFail
	}
	if !failed {
		last.Result, last.Message = resource.ConnectionFail, "region status transport unavailable"
		if h.regionStatus != nil {
			if _, err := h.regionStatus(ctx, v.RegionEndpoint); err != nil {
				last.Message = h.regionFailure(ctx, err)
			} else {
				last.Result, last.Message = resource.ConnectionPass, "regionapi mTLS status read succeeded"
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{Steps: append(steps, last)})
}
