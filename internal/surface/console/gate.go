package console

import (
	"context"
	"net/http"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// authorization is what one route is authorized as: an IAM action and the
// resource ARN, both derived from the request.
type authorization func(r *http.Request) (action, arn string)

func ec2(action string) authorization {
	return func(*http.Request) (string, string) { return "ec2:" + action, "*" }
}

func s3Bucket(action string) authorization {
	return func(r *http.Request) (string, string) { return "s3:" + action, "arn:vws:s3:::" + r.PathValue("name") }
}

func s3Object(action string) authorization {
	return func(r *http.Request) (string, string) {
		return "s3:" + action, "arn:vws:s3:::" + r.PathValue("name") + "/" + r.PathValue("key")
	}
}

// routeAction names the IAM action of a console route pattern. Mutations are
// ec2:<Action>; reads are the matching Describe; buckets and objects use the
// S3 action and ARN that the S3 API uses. The auth routes are authenticated
// but not authorized, like sts:GetCallerIdentity.
func routeAction(pattern string) (authorization, bool) {
	for _, a := range resource.Actions() {
		if m, p, _ := (&handler{}).mutation(a); m+" "+p == pattern && p != "/api/v1/unsupported" {
			return ec2(a.String()), true
		}
	}
	z, ok := map[string]authorization{
		"GET /api/v1/admin/regions":                 nil,
		"POST /api/v1/admin/regions":                nil,
		"POST /api/v1/admin/regions/test":           nil,
		"POST /api/v1/admin/regions/{name}/test":    nil,
		"PATCH /api/v1/admin/regions/{name}":        nil,
		"DELETE /api/v1/admin/regions/{name}":       nil,
		"GET /api/v1/regions":                       ec2("DescribeRegions"),
		"GET /api/v1/regions/{region}/capabilities": ec2("DescribeRegions"),
		"GET /api/v1/admin/regions/{name}":          nil,
		"GET /api/v1/admin/regions/{name}/health":   nil,
		"GET /api/v1/admin/aws-accounts":            nil,
		"GET /api/v1/admin/aws-accounts/{id}":       nil,
		"POST /api/v1/admin/aws-accounts":           nil,
		"POST /api/v1/admin/aws-accounts/test":      nil,
		"POST /api/v1/admin/aws-accounts/{id}/test": nil,
		"PATCH /api/v1/admin/aws-accounts/{id}":     nil,
		"DELETE /api/v1/admin/aws-accounts/{id}":    nil,
		"GET /api/v1/admin/permissions":             nil,
		"GET /api/v1/admin/projects/{project}":      nil,
		"PUT /api/v1/admin/projects/{project}":      nil,
		"GET /api/v1/instances":                     ec2("DescribeInstances"),
		"GET /api/v1/instances/{id}":                ec2("DescribeInstances"),
		"POST /api/v1/instances/stop":               ec2("StopInstances"),
		"POST /api/v1/instances/start":              ec2("StartInstances"),
		"POST /api/v1/instances/terminate":          ec2("TerminateInstances"),
		"GET /api/v1/operations/{id}": func(*http.Request) (string, string) {
			return "vws:GetOperation", "*"
		},
		"GET /api/v1/subnets":                   ec2("DescribeSubnets"),
		"GET /api/v1/subnets/{id}":              ec2("DescribeSubnets"),
		"GET /api/v1/vpcs":                      ec2("DescribeVpcs"),
		"GET /api/v1/vpcs/{id}":                 ec2("DescribeVpcs"),
		"POST /api/v1/vpcs/{id}/tags":           ec2("CreateTags"),
		"POST /api/v1/subnets/{id}/tags":        ec2("CreateTags"),
		"POST /api/v1/vpcs/{id}/tags/delete":    ec2("DeleteTags"),
		"POST /api/v1/subnets/{id}/tags/delete": ec2("DeleteTags"),
		"POST /api/v1/volumes/{id}/tags":        ec2("CreateTags"),
		"POST /api/v1/volumes/{id}/tags/delete": ec2("DeleteTags"),
		"GET /api/v1/volumes":                   ec2("DescribeVolumes"),
		"GET /api/v1/volumes/{id}":              ec2("DescribeVolumes"),
		"GET /api/v1/images":                    ec2("DescribeImages"),
		"GET /api/v1/instance-types":            ec2("DescribeInstanceTypes"),
		"GET /api/v1/key-pairs":                 ec2("DescribeKeyPairs"),
		"GET /api/v1/security-groups":           ec2("DescribeSecurityGroups"),
		"GET /api/v1/addresses":                 ec2("DescribeAddresses"),
		"GET /api/v1/snapshots":                 ec2("DescribeSnapshots"),
		"GET /api/v1/buckets": func(*http.Request) (string, string) {
			return "s3:ListAllMyBuckets", "arn:vws:s3:::*"
		},
		"PUT /api/v1/buckets/{name}":                     s3Bucket("CreateBucket"),
		"GET /api/v1/buckets/{name}":                     s3Bucket("ListBucket"),
		"DELETE /api/v1/buckets/{name}":                  s3Bucket("DeleteBucket"),
		routePutObject:                                   s3Object("PutObject"),
		"GET /api/v1/buckets/{name}/objects/{key...}":    s3Object("GetObject"),
		"DELETE /api/v1/buckets/{name}/objects/{key...}": s3Object("DeleteObject"),
		routeLogin:   nil,
		routeLogout:  nil,
		routeSession: nil,
		routeConsole: func(*http.Request) (string, string) {
			return "vws:OpenConsole", "*"
		},
	}[pattern]
	return z, ok
}

// Routes lists every console route pattern.
func Routes() []string {
	h := &handler{}
	h.routes(http.NewServeMux())
	return h.patterns
}

// gate authenticates every routed request, checks CSRF on cookie sessions,
// and authorizes the route's IAM action before the handler runs. A route
// with no entry in routeAction is refused: authorization fails closed.
func (h *handler) gate(w http.ResponseWriter, r *http.Request) {
	_, pattern := h.mux.Handler(r)
	if h.loginOff && h.signInOff(w, r, pattern) {
		return
	}
	if pattern == "" || pattern == routeLogin {
		h.mux.ServeHTTP(w, r)
		return
	}
	authz, known := routeAction(pattern)
	if !known {
		writeErr(w, r, resource.Denied("route has no IAM action"))
		return
	}
	var c resource.Caller
	if action := accountAction(pattern); action != "" {
		out := &adminResponse{ResponseWriter: w, status: http.StatusOK}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/aws-accounts/")
		if len(id) == 12 && strings.Trim(id, "0123456789") == "" {
			out.id = id
		}
		w = out
		start := h.now()
		defer func() { h.auditAccount(out, r, c, action, start) }()
	}
	isAdmin := strings.HasPrefix(r.URL.Path, "/api/v1/admin/")
	if isAdmin {
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.Header.Get("Authorization") == "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if _, err := r.Cookie(SessionCookie); err == nil && !h.browserWriteOK(w, r, pattern != routePutObject) {
			return
		}
	}
	c, err := h.authenticate(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if pattern == routeConsole {
		if c.Subject != "session" || r.Header.Get("Authorization") != "" {
			writeErr(w, r, resource.Unauthenticated("console session required"))
			return
		}
		if len(r.Header.Values("Origin")) != 1 {
			writeErr(w, r, resource.Denied("one origin required"))
			return
		}
		if !h.browserWriteOK(w, r, false) {
			return
		}
	}
	if !isAdmin && pattern != routeSession && pattern != routeLogout {
		if c.Region == "" {
			c.Region = h.region
		}
		if len(r.Header.Values("X-Vws-Region")) > 1 {
			writeErr(w, r, resource.Invalid("region", "expected one region header"))
			return
		}
		c, err = h.svc.RequestRegion(r.Context(), c, r.Header.Get("X-Vws-Region"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if isAdmin {
		if !c.Root {
			if pattern == "GET /api/v1/admin/permissions" {
				writeJSON(w, http.StatusForbidden, permissionsBody{Permissions: []string{}})
			} else {
				writeErr(w, r, resource.Denied("administrator required"))
			}
			return
		}
		action := "vws:AdminRead"
		if r.Method != http.MethodGet {
			action = "vws:AdminWrite"
		}
		if wait, err := h.requests.Take(c.Account, action); err != nil {
			retryAfter(w, wait)
			writeErr(w, r, err)
			return
		}
	}
	if authz != nil {
		action, arn := authz(r)
		if wait, err := h.requests.Take(c.Account, action); err != nil {
			retryAfter(w, wait)
			writeErr(w, r, err)
			return
		}
		if err := iam.Check(r.Context(), h.iam, c, action, arn); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	h.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
}
