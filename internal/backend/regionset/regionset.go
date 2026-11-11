// Package regionset combines read-only regional inventories into backend.Set.
package regionset

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Resolver supplies a registered region's transport. The caller owns its lifetime.
type Resolver func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error)

// New reads the catalog on each request. Mutations remain unsupported until the
// region transport supports them. AWS raw proxy routing is separate.
func New(catalog backend.RegionCatalog, resolve Resolver) (backend.Set, error) {
	if catalog == nil || resolve == nil {
		return backend.Set{}, resource.Invalid("regions", "catalog and resolver are required")
	}
	r := &router{catalog, resolve}
	base, err := regionclient.New(r)
	if err != nil {
		return backend.Set{}, err
	}
	return backend.Set{
		Compute: compute{base.Compute, r},
		Network: network{base.Network, r},
		Storage: storage{base.Storage, r},
	}, nil
}

type router struct {
	catalog backend.RegionCatalog
	resolve Resolver
}

func (r *router) regions(ctx context.Context) ([]backend.ProxmoxRegion, error) {
	regions, err := r.catalog.ProxmoxRegions(ctx)
	if err != nil {
		return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region catalog unavailable"}
	}
	slices.SortFunc(regions, func(a, b backend.ProxmoxRegion) int { return strings.Compare(a.Name, b.Name) })
	return regions, nil
}

func (r *router) Call(ctx context.Context, service, method string, s backend.Scope, q, dst any) error {
	regions, err := r.regions(ctx)
	if err != nil {
		return err
	}
	for _, region := range regions {
		if region.Name == s.Region && s.Region != "all" {
			return r.call(ctx, region, service, method, s, q, dst)
		}
	}
	return resource.Invalid("region", "a registered region is required")
}

func (r *router) call(ctx context.Context, region backend.ProxmoxRegion,
	service, method string, s backend.Scope, q, dst any,
) error {
	t, err := r.resolve(ctx, region)
	if err != nil {
		return fmt.Errorf("resolve region: %w", err)
	}
	if err := t.Call(ctx, service, method, s, q, dst); err != nil {
		return fmt.Errorf("read region: %w", err)
	}
	return nil
}

func cursors(scope string, token string, regions []backend.ProxmoxRegion) (map[string]string, error) {
	pending := map[string]string{}
	for _, region := range regions {
		if scope == "all" || scope == region.Name {
			pending[region.Name] = ""
		}
	}
	if scope != "all" && len(pending) == 0 {
		return nil, resource.Invalid("region", "a registered region is required")
	}
	if token == "" {
		return pending, nil
	}
	if len(token) > 1<<20 {
		return nil, resource.Invalid("pageToken", "regional cursor exceeds the limit")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || !utf8.Valid(raw) {
		return nil, resource.Invalid("pageToken", "malformed regional cursor")
	}
	region, value, ok := strings.Cut(string(raw), ":")
	if !ok || region != scope {
		return nil, resource.Invalid("pageToken", "cursor belongs to another region")
	}
	if scope != "all" {
		if !validCursor(value) {
			return nil, resource.Invalid("pageToken", "malformed regional cursor")
		}
		pending[scope] = value
		return pending, nil
	}
	var resumed map[string]string
	if err := json.Unmarshal([]byte(value), &resumed); err != nil || len(resumed) == 0 {
		return nil, resource.Invalid("pageToken", "malformed regional cursors")
	}
	for name, cursor := range resumed {
		if _, ok := pending[name]; !ok || !validCursor(cursor) {
			return nil, resource.Invalid("pageToken", "cursor region or value is invalid")
		}
	}
	return resumed, nil
}

func validCursor(token string) bool {
	return len(token) <= 4096 && utf8.ValidString(token) && !strings.ContainsFunc(token, unicode.IsControl)
}

func nextToken(scope string, pending map[string]string) (string, error) {
	if len(pending) == 0 {
		return "", nil
	}
	value := pending[scope]
	if scope == "all" {
		raw, err := json.Marshal(pending)
		if err != nil {
			return "", fmt.Errorf("encode regional cursors: %w", err)
		}
		value = string(raw)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(scope + ":" + value)), nil
}

type result[T any] struct {
	page resource.Page[T]
	err  error
}

func readRegion[T any](ctx context.Context, r *router, region backend.ProxmoxRegion,
	s backend.Scope, page resource.PageRequest, query func(resource.PageRequest) any, service, method string,
) result[T] {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan result[T], 1)
	// A late transport owns its result and can finish without touching the
	// collector or blocking a send after the request has ended.
	go func() {
		var p resource.Page[T]
		err := r.call(ctx, region, service, method, s, query(page), &p)
		done <- result[T]{p, err}
	}()
	select {
	case got := <-done:
		return got
	case <-ctx.Done():
		return result[T]{err: ctx.Err()}
	}
}

func list[T any](ctx context.Context, r *router, s backend.Scope, page resource.PageRequest,
	query func(resource.PageRequest) any, service, method string,
) (resource.Page[T], error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	regions, err := r.regions(ctx)
	if err != nil {
		return resource.Page[T]{}, err
	}
	pending, err := cursors(s.Region, page.Token, regions)
	if err != nil {
		return resource.Page[T]{}, err
	}
	type regional struct {
		name string
		result[T]
	}
	done := make(chan regional, len(pending))
	for _, region := range regions {
		token, ok := pending[region.Name]
		if !ok {
			continue
		}
		go func() {
			scope, req := s, page
			scope.Region, req.Token = region.Name, token
			done <- regional{region.Name, readRegion[T](ctx, r, region, scope, req, query, service, method)}
		}()
	}
	results := make(map[string]result[T], len(pending))
	for len(results) < len(pending) {
		select {
		case got := <-done:
			results[got.name] = got.result
		case <-ctx.Done():
			// Retain any successful results already delivered at the deadline.
			for len(done) > 0 {
				got := <-done
				results[got.name] = got.result
			}
			for name := range pending {
				if _, ok := results[name]; !ok {
					results[name] = result[T]{err: ctx.Err()}
				}
			}
		}
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return resource.Page[T]{}, err
	}
	var out resource.Page[T]
	for _, region := range regions {
		got, ok := results[region.Name]
		if !ok {
			continue
		}
		if got.err != nil {
			message := "region unavailable"
			if errors.Is(got.err, context.DeadlineExceeded) {
				message = "region timed out"
			}
			if s.Region != "all" {
				var public *resource.Error
				if errors.As(got.err, &public) {
					return resource.Page[T]{}, public
				}
				return resource.Page[T]{}, &resource.Error{Code: resource.CodeUnavailable, Message: message}
			}
			out.Partial = append(out.Partial, resource.Partial{Region: region.Name, Error: message})
			continue
		}
		out.Items = append(out.Items, got.page.Items...)
		if got.page.NextToken == "" {
			delete(pending, region.Name)
		} else {
			pending[region.Name] = got.page.NextToken
		}
	}
	out.NextToken, err = nextToken(s.Region, pending)
	return out, err
}
