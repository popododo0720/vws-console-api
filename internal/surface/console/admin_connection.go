package console

import (
	"context"
	"net/http"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

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
