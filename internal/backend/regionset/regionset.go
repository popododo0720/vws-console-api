// Package regionset routes regional backends and combines their inventories.
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

const maxCursorBytes = 4096

// New reads the catalog on each request. AWS raw proxy routing is separate.
func New(catalog backend.RegionCatalog, resolve Resolver, keys ...keyPairClient) (backend.Set, error) {
	if catalog == nil || resolve == nil {
		return backend.Set{}, resource.Invalid("regions", "catalog and resolver are required")
	}
	r := &router{catalog, resolve}
	base, err := regionclient.New(r)
	if err != nil {
		return backend.Set{}, err
	}
	var keyPairs keyPairClient
	if len(keys) != 0 {
		keyPairs = keys[0]
	}
	return backend.Set{
		Compute: compute{base.Compute, r, keyPairs},
		Network: network{base.Network, r},
		Storage: storage{base.Storage, r},
		Console: r,
		Usage:   base.Usage,
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

func (r *router) Call(ctx context.Context, service, method string, input, q, dst any) error {
	var s backend.Scope
	switch value := input.(type) {
	case backend.Scope:
		s = value
	case backend.Mutation:
		s = value.Scope
	default:
		return resource.Invalid("scope", "expected scope or mutation")
	}
	regions, err := r.regions(ctx)
	if err != nil {
		return err
	}
	for _, region := range regions {
		if region.Name == s.Region && s.Region != "all" {
			if mutation, ok := input.(backend.Mutation); ok {
				mutation.Scope, err = r.boundScope(ctx, s)
				if err != nil {
					return err
				}
				t, err := r.resolve(ctx, region)
				if err == nil {
					err = t.Call(ctx, service, method, mutation, q, dst)
				}
				return regionalError(err)
			}
			return r.call(ctx, region, service, method, s, q, dst)
		}
	}
	return resource.Invalid("region", "a registered region is required")
}

func (r *router) call(ctx context.Context, region backend.ProxmoxRegion,
	service, method string, s backend.Scope, q, dst any,
) error {
	if caps, ok := r.catalog.(backend.Capabilities); ok {
		doc, err := caps.RegionCapabilities(ctx, s.Region)
		if err != nil {
			return regionalError(err)
		}
		if doc.Actions["ec2:"+method].State == resource.ActionEmpty {
			return nil
		}
	}
	s, err := r.boundScope(ctx, s)
	if err != nil {
		return err
	}
	t, err := r.resolve(ctx, region)
	if err == nil {
		err = t.Call(ctx, service, method, s, q, dst)
	}
	return regionalError(err)
}

func (r *router) boundScope(ctx context.Context, s backend.Scope) (backend.Scope, error) {
	s.Pool = s.Account.String()
	if pools, ok := r.catalog.(backend.ProjectPools); ok {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		pool, err := pools.ProjectPool(ctx, s.Account, s.Region)
		if err != nil {
			return backend.Scope{}, regionalError(err)
		}
		s.Pool = pool
	}
	return s, nil
}

func regionalError(err error) error {
	if err == nil {
		return nil
	}
	var public *resource.Error
	if errors.As(err, &public) && public.Code != resource.CodeUnavailable {
		if public.Unwrap() == nil {
			return public
		}
		return public.WithCause(nil)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return (&resource.Error{Code: resource.CodeUnavailable, Message: "region timed out"}).
			WithCause(context.DeadlineExceeded)
	}
	return &resource.Error{Code: resource.CodeUnavailable, Message: "region unavailable"}
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
	maxRaw := len(scope) + 1 + maxCursorBytes
	if scope == "all" {
		maxRaw = len(scope) + 3
		for name := range pending {
			// JSON can expand each key or cursor byte to a six-byte escape.
			maxRaw += 6*(len(name)+maxCursorBytes) + 6
		}
	}
	if len(token) > base64.RawURLEncoding.EncodedLen(maxRaw) {
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
	return len(token) <= maxCursorBytes && utf8.ValidString(token) && !strings.ContainsFunc(token, unicode.IsControl)
}

func nextToken(scope string, pending map[string]string) (string, error) {
	if len(pending) == 0 {
		return "", nil
	}
	for _, cursor := range pending {
		if !validCursor(cursor) {
			return "", resource.Internal(errors.New("region returned a malformed cursor"))
		}
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
				return resource.Page[T]{}, regionalError(got.err)
			}
			out.Partial = append(out.Partial, resource.Partial{Region: region.Name, Error: message})
			continue
		}
		for i := range got.page.Items {
			if regional, ok := any(&got.page.Items[i]).(interface{ SetRegion(string) }); ok {
				regional.SetRegion(region.Name)
			}
		}
		out.Items = append(out.Items, got.page.Items...)
		out.Partial = append(out.Partial, got.page.Partial...)
		out.Stale = out.Stale || got.page.Stale
		if got.page.NextToken == "" {
			delete(pending, region.Name)
		} else {
			pending[region.Name] = got.page.NextToken
		}
	}
	out.NextToken, err = nextToken(s.Region, pending)
	return out, err
}
