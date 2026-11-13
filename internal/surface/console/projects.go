package console

import (
	"net/http"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type projectRegion struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Pool string `json:"pool,omitempty"`
}

type projectView struct {
	Project string          `json:"project"`
	Regions []projectRegion `json:"regions"`
}

// listProjects returns the projects the caller may use: the project of the
// caller's account, as an AWS identity belongs to one account. It carries
// region names and pools only, never AWS account ids or credentials.
func (h *handler) listProjects(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, r, resource.Invalid("query", "query parameters are not supported"))
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if h.registry == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin registry unavailable"})
		return
	}
	v, err := h.projectMapping(r.Context(), c.Account.String())
	if err != nil {
		projectReadError(w, r, err)
		return
	}
	view := projectView{Project: v.Project, Regions: []projectRegion{}}
	slices.SortFunc(v.Pools, func(a, b store.ProjectPool) int { return strings.Compare(a.Region, b.Region) })
	for _, pool := range v.Pools {
		view.Regions = append(view.Regions, projectRegion{Name: pool.Region, Kind: "pve", Pool: pool.Pool})
	}
	// AWS forwarding refuses every region when a mapped account cannot be
	// read, and a region that more than one mapped account allows.
	allowedBy := map[string]int{}
	for _, id := range v.AWSAccounts {
		account, err := h.registry.AWSAccounts().Get(r.Context(), id)
		if err != nil {
			h.log.WarnContext(r.Context(), "project AWS regions omitted: a mapped AWS account is unreadable")
			clear(allowedBy)
			break
		}
		for _, name := range account.AllowedRegions {
			allowedBy[name]++
		}
	}
	var aws []string
	for name, n := range allowedBy {
		if n == 1 {
			aws = append(aws, name)
		}
	}
	slices.Sort(aws)
	for _, name := range aws {
		view.Regions = append(view.Regions, projectRegion{Name: name, Kind: "aws"})
	}
	writeJSON(w, http.StatusOK, struct {
		Items []projectView `json:"items"`
	}{Items: []projectView{view}})
}

func listProjectsAction(*http.Request) (string, string) { return "vws:ListProjects", "*" }

func projectReadError(w http.ResponseWriter, r *http.Request, err error) {
	failed := &resource.Error{Code: resource.CodeUnavailable, Message: "project registry read failed"}
	writeErr(w, r, failed.WithCause(err))
}
