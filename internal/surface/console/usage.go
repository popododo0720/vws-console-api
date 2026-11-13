package console

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type usageRegion struct {
	Region     string               `json:"region"`
	Allocation *resource.Allocation `json:"allocation,omitempty"`
	Error      string               `json:"error,omitempty"`
}

type projectUsage struct {
	Project string        `json:"project"`
	Regions []usageRegion `json:"regions"`
}

func usageWindow(raw string) (string, string, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", "", resource.Invalid("query", "invalid query encoding")
	}
	for key, values := range q {
		if (key != "from" && key != "to") || len(values) != 1 {
			return "", "", resource.Invalid("query", "expected one from and one to")
		}
	}
	from, to := q.Get("from"), q.Get("to")
	start, startErr := time.Parse(time.DateOnly, from)
	end, endErr := time.Parse(time.DateOnly, to)
	if startErr != nil || endErr != nil || !start.Before(end) || end.Sub(start) > 366*24*time.Hour {
		return "", "", resource.Invalid("window", "from and to must be YYYY-MM-DD, from < to, at most 366 days")
	}
	return from, to, nil
}

func (h *handler) usage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	from, to, err := usageWindow(r.URL.RawQuery)
	if err != nil {
		writeErr(w, r, err)
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	mapping, err := h.projectMapping(ctx, c.Account.String())
	if err != nil {
		projectReadError(w, r, err)
		return
	}
	slices.SortFunc(mapping.Pools, func(a, b store.ProjectPool) int { return strings.Compare(a.Region, b.Region) })
	view := projectUsage{Project: mapping.Project, Regions: []usageRegion{}}
	for _, pool := range mapping.Pools {
		c.Region = pool.Region
		allocation, err := h.svc.GetAllocation(ctx, c)
		row := usageRegion{Region: pool.Region}
		if err != nil {
			row.Error = "Unavailable"
			h.log.WarnContext(ctx, "usage allocation unavailable")
		} else {
			row.Allocation = &allocation
		}
		view.Regions = append(view.Regions, row)
	}
	writeJSON(w, http.StatusOK, struct {
		From  string         `json:"from"`
		To    string         `json:"to"`
		Items []projectUsage `json:"items"`
	}{From: from, To: to, Items: []projectUsage{view}})
}
