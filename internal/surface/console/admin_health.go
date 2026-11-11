package console

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) adminHealth(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	name := r.PathValue("name")
	if !regexp.MustCompile(`^pve-[a-z0-9]+(-[a-z0-9]+)*-[0-9]+$`).MatchString(name) || len(name) > 63 {
		writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	region, err := h.registry.Regions().Get(ctx, name)
	if err != nil {
		adminError(w, r, err)
		return
	}
	if h.regionStatus == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "region status transport unavailable"})
		return
	}
	status, err := h.regionStatus(ctx, region.RegionEndpoint)
	state := "ok"
	if err != nil {
		state = "unreachable"
		status = resource.RegionStatus{
			Nodes:     []resource.RegionNode{},
			LastError: &resource.RegionStatusError{Time: h.now().UTC(), Message: err.Error()},
		}
	}
	writeJSON(w, http.StatusOK, struct {
		resource.RegionStatus
		Status    string    `json:"status"`
		CheckedAt time.Time `json:"checkedAt"`
	}{RegionStatus: status, Status: state, CheckedAt: h.now().UTC()})
}
