package console

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) projectID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !h.adminReady(w, r) {
		return "", false
	}
	id := r.PathValue("project")
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(id) {
		writeErr(w, r, resource.Invalid("project", "must be 12 digits"))
		return "", false
	}
	setAuditAccount(w, id)
	return id, true
}

func (h *handler) adminProject(w http.ResponseWriter, r *http.Request) {
	id, ok := h.projectID(w, r)
	if !ok {
		return
	}
	v, err := h.projectMapping(r.Context(), id)
	if err != nil {
		adminError(w, r, err)
		return
	}
	writeProject(w, v)
}

// projectMapping reads a project's mapping. A project without one has the
// pool named after it in every registered region and no AWS accounts.
func (h *handler) projectMapping(ctx context.Context, id string) (store.Project, error) {
	v, err := h.registry.Projects().Get(ctx, id)
	if !errors.Is(err, store.ErrNotFound) {
		return v, err
	}
	regions, skipped, err := h.registry.Regions().List(ctx)
	if err != nil {
		return store.Project{}, err
	}
	if len(skipped) != 0 {
		h.log.WarnContext(ctx, "admin registry skipped undecodable records", slog.Int("count", len(skipped)))
	}
	v = store.Project{Project: id, Pools: []store.ProjectPool{}, AWSAccounts: []string{}}
	for _, region := range regions {
		v.Pools = append(v.Pools, store.ProjectPool{Region: region.Name, Pool: id})
	}
	return v, nil
}

func (h *handler) adminMapProject(w http.ResponseWriter, r *http.Request) {
	id, ok := h.projectID(w, r)
	if !ok {
		return
	}
	if h.adminKey == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin writes require credentials.kek_file"})
		return
	}
	if h.audit == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "project writes require audit logging"})
		return
	}
	match := r.Header.Get("If-Match")
	if match == "" {
		writeErr(w, r, resource.Invalid("If-Match", "required; use the GET ETag"))
		return
	}
	var in *struct {
		Project     *string              `json:"project"`
		Pools       *[]store.ProjectPool `json:"pools"`
		AWSAccounts *[]string            `json:"awsAccounts"`
	}
	if err := decode(w, r, &in); err != nil {
		writeErr(w, r, err)
		return
	}
	if in == nil || in.Pools == nil || in.AWSAccounts == nil {
		writeErr(w, r, resource.Invalid("body", "pools and awsAccounts arrays are required"))
		return
	}
	if in.Project != nil && *in.Project != id {
		writeErr(w, r, resource.Invalid("project", "must match path"))
		return
	}
	v := store.Project{Project: id, Pools: *in.Pools, AWSAccounts: *in.AWSAccounts}
	if err := store.ValidateProject(v); err != nil {
		writeErr(w, r, err)
		return
	}
	old, err := h.registry.Projects().Get(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		adminError(w, r, err)
		return
	}
	if match != strconv.Quote(strconv.FormatInt(int64(old.Version), 10)) {
		adminError(w, r, store.ErrConflict)
		return
	}
	v.Version = old.Version
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if err := h.validateProjectMapping(ctx, v); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err = h.registry.Projects().Put(ctx, v)
	if conflict, ok := errors.AsType[*store.PoolConflictError](err); ok {
		writeErr(w, r, &resource.Error{Code: resource.CodeConflict, Message: conflict.Error()})
		return
	}
	if err != nil {
		adminError(w, r, err)
		return
	}
	writeProject(w, v)
}

func (h *handler) validateProjectMapping(ctx context.Context, v store.Project) error {
	for _, id := range v.AWSAccounts {
		if _, err := h.registry.AWSAccounts().Get(ctx, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return resource.Invalid("awsAccounts", "unregistered AWS account "+id)
			}
			return (&resource.Error{Code: resource.CodeUnavailable, Message: "AWS account registry unavailable"}).WithCause(err)
		}
	}
	for _, pool := range v.Pools {
		region, err := h.registry.Regions().Get(ctx, pool.Region)
		if errors.Is(err, store.ErrNotFound) {
			return resource.Invalid("pools", "unregistered region "+pool.Region)
		}
		if err != nil {
			return (&resource.Error{Code: resource.CodeUnavailable, Message: "region registry unavailable"}).WithCause(err)
		}
		if h.regionPool == nil {
			return &resource.Error{Code: resource.CodeUnavailable, Message: "region pool transport unavailable"}
		}
		exists, err := func() (bool, error) {
			callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return h.regionPool(callCtx, region.RegionEndpoint, pool.Pool)
		}()
		if err != nil {
			return (&resource.Error{Code: resource.CodeUnavailable, Message: h.regionFailure(ctx, err)}).WithCause(err)
		}
		if !exists {
			return resource.Invalid("pools", "pool "+pool.Pool+" does not exist in region "+pool.Region)
		}
	}
	return nil
}

func writeProject(w http.ResponseWriter, v store.Project) {
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	writeJSON(w, http.StatusOK, v)
}
