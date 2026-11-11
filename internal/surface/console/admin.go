package console

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type permissionsBody struct {
	Permissions []string `json:"permissions"`
}

func (h *handler) adminPermissions(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, r, resource.Invalid("query", "query parameters are not supported"))
		return
	}
	writeJSON(w, http.StatusOK, permissionsBody{Permissions: []string{
		"vws:AdminListRegions", "vws:AdminListAwsAccounts",
		"vws:AdminRegisterAwsAccount", "vws:AdminUpdateAwsAccount", "vws:AdminRemoveAwsAccount",
		"vws:AdminRegisterRegion", "vws:AdminUpdateRegion", "vws:AdminRemoveRegion",
	}})
}

func (h *handler) adminReady(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		writeErr(w, r, resource.Invalid("query", "query parameters are not supported"))
		return false
	}
	if h.registry == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin registry unavailable"})
		return false
	}
	return true
}

func (h *handler) adminRegions(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	items, skipped, err := h.registry.Regions().List(r.Context())
	adminList(w, r, h.log, items, skipped, err)
}

func (h *handler) adminAccounts(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	items, skipped, err := h.registry.AWSAccounts().List(r.Context())
	views := make([]accountView, 0, len(items))
	for _, item := range items {
		views = append(views, viewAccount(item))
	}
	adminList(w, r, h.log, views, skipped, err)
}

func adminList[T any](
	w http.ResponseWriter, r *http.Request, log *slog.Logger, items []T, skipped []store.Undecodable, err error,
) {
	if err != nil {
		adminError(w, r, err)
		return
	}
	if len(skipped) != 0 {
		log.WarnContext(r.Context(), "admin registry skipped undecodable records", slog.Int("count", len(skipped)))
	}
	// Versions are excluded from stored JSON, so include them in the collection validator.
	data, err := json.Marshal(items)
	if err != nil {
		adminError(w, r, err)
		return
	}
	versions := make([]store.Version, 0, len(items))
	for _, item := range items {
		switch v := any(item).(type) {
		case store.Region:
			versions = append(versions, v.Version)
		case accountView:
			versions = append(versions, v.Version)
		}
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256(fmt.Appendf(data, "%v", versions))))
	writeJSON(w, http.StatusOK, struct {
		Items []T `json:"items"`
	}{Items: items})
}

func (h *handler) adminRegion(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	name := r.PathValue("name")
	if !regexp.MustCompile(`^pve-[a-z0-9]+(-[a-z0-9]+)*-[0-9]+$`).MatchString(name) || len(name) > 63 {
		writeErr(w, r, resource.Invalid("name", "invalid Proxmox region name"))
		return
	}
	v, err := h.registry.Regions().Get(r.Context(), name)
	if err != nil {
		adminError(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	writeJSON(w, http.StatusOK, v)
}

func (h *handler) adminAccount(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	id := r.PathValue("id")
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(id) {
		writeErr(w, r, resource.Invalid("id", "invalid AWS account id"))
		return
	}
	v, err := h.registry.AWSAccounts().Get(r.Context(), id)
	if err != nil {
		adminError(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	writeJSON(w, http.StatusOK, viewAccount(v))
}

func adminError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrConflict) {
		writeErr(w, r, &resource.Error{Code: resource.CodeConflict, Message: "registration already exists or changed"})
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, r, &resource.Error{Code: resource.CodeNotFound, Message: "registration not found"})
		return
	}
	writeErr(w, r, (&resource.Error{Code: resource.CodeUnavailable, Message: "admin registry read failed"}).WithCause(err))
}
