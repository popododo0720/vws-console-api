// Package router selects a regional surface without consuming its request body.
package router

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Config supplies authenticated surface handlers and their wire error renderer.
// AWS takes EC2 requests for an AWS region; Forward takes every other service
// for an AWS region. A nil handler refuses its requests.
type Config struct {
	Regions backend.RegionCatalog
	Local   http.Handler
	AWS     http.Handler
	Forward http.Handler
	Error   func(http.ResponseWriter, *http.Request, error)
}

// New routes by the current registry; each destination still verifies the signature.
func New(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		region, service, err := sigv4.CredentialScope(r.Header.Get("Authorization"))
		if err == nil && len(r.Header.Values("Authorization")) != 1 {
			err = sigv4.Reject(sigv4.FailureMalformed, resource.Invalid("Authorization", "repeated"))
		}
		if err != nil {
			cfg.Error(w, r, err)
			return
		}
		if service == sigv4.ServiceIAM || service == sigv4.ServiceSTS {
			cfg.Local.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		aws, err := destination(ctx, cfg.Regions, region)
		if err != nil {
			cfg.Error(w, r, err)
			return
		}
		var next http.Handler
		switch {
		case !aws && (service == sigv4.ServiceEC2 || service == sigv4.ServiceS3):
			next = cfg.Local
		case aws && service == sigv4.ServiceEC2:
			next = cfg.AWS
		case aws:
			next = cfg.Forward
		}
		if next == nil {
			cfg.Error(w, r, sigv4.Reject(sigv4.FailureMalformed, resource.Unauthenticated("credential scope rejected")))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func destination(ctx context.Context, catalog backend.RegionCatalog, region string) (bool, error) {
	if catalog != nil {
		if strings.HasPrefix(region, "pve-") {
			regions, err := catalog.ProxmoxRegions(ctx)
			if err != nil {
				return false, resource.Internal(fmt.Errorf("read region catalog: %w", err))
			}
			if slices.ContainsFunc(regions, func(r backend.ProxmoxRegion) bool { return r.Name == region }) {
				return false, nil
			}
		} else {
			accounts, err := catalog.AWSAccounts(ctx)
			if err != nil {
				return false, resource.Internal(fmt.Errorf("read region catalog: %w", err))
			}
			if slices.ContainsFunc(accounts, func(a backend.AWSAccount) bool {
				return slices.Contains(a.AllowedRegions, region)
			}) {
				return true, nil
			}
		}
	}
	return false, sigv4.Reject(sigv4.FailureMalformed, resource.Unauthenticated("credential scope rejected"))
}
