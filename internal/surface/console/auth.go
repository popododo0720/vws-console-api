package console

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Console sign-in wire names.
const (
	// SessionCookie carries the session token. It is HttpOnly, so page
	// scripts never see it.
	SessionCookie = "vws_session"
	// CSRFCookie carries the CSRF token for the page to echo in CSRFHeader on
	// every request that changes state.
	CSRFCookie = "vws_csrf"
	// CSRFHeader must equal the session's CSRF token on a cookie-authenticated
	// request that is not GET or HEAD.
	CSRFHeader = "X-CSRF-Token"

	maxLoginBody = 4 << 10
)

// Auth routes, served before the gate authenticates.
const (
	routeLogin   = "POST /api/v1/auth/login"
	routeLogout  = "POST /api/v1/auth/logout"
	routeSession = "GET /api/v1/auth/session"
)

// csrfToken derives the CSRF token from the session token. It needs no
// storage, works on every replica, and cannot be forged without the HttpOnly
// session cookie.
func csrfToken(session string) string {
	sum := sha256.Sum256([]byte("vws-console-csrf\x00" + session))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type callerKey struct{}

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
		"GET /api/v1/instances":                          ec2("DescribeInstances"),
		"GET /api/v1/instances/{id}":                     ec2("DescribeInstances"),
		"POST /api/v1/instances/stop":                    ec2("StopInstances"),
		"POST /api/v1/instances/start":                   ec2("StartInstances"),
		"POST /api/v1/instances/terminate":               ec2("TerminateInstances"),
		"GET /api/v1/operations/{id}":                    func(*http.Request) (string, string) { return "vws:GetOperation", "*" },
		"GET /api/v1/subnets":                            ec2("DescribeSubnets"),
		"GET /api/v1/subnets/{id}":                       ec2("DescribeSubnets"),
		"GET /api/v1/vpcs":                               ec2("DescribeVpcs"),
		"GET /api/v1/vpcs/{id}":                          ec2("DescribeVpcs"),
		"POST /api/v1/vpcs/{id}/tags":                    ec2("CreateTags"),
		"POST /api/v1/subnets/{id}/tags":                 ec2("CreateTags"),
		"GET /api/v1/volumes":                            ec2("DescribeVolumes"),
		"GET /api/v1/volumes/{id}":                       ec2("DescribeVolumes"),
		"GET /api/v1/images":                             ec2("DescribeImages"),
		"GET /api/v1/instance-types":                     ec2("DescribeInstanceTypes"),
		"GET /api/v1/key-pairs":                          ec2("DescribeKeyPairs"),
		"GET /api/v1/security-groups":                    ec2("DescribeSecurityGroups"),
		"GET /api/v1/addresses":                          ec2("DescribeAddresses"),
		"GET /api/v1/snapshots":                          ec2("DescribeSnapshots"),
		"GET /api/v1/buckets":                            func(*http.Request) (string, string) { return "s3:ListAllMyBuckets", "arn:vws:s3:::*" },
		"PUT /api/v1/buckets/{name}":                     s3Bucket("CreateBucket"),
		"GET /api/v1/buckets/{name}":                     s3Bucket("ListBucket"),
		"DELETE /api/v1/buckets/{name}":                  s3Bucket("DeleteBucket"),
		"PUT /api/v1/buckets/{name}/objects/{key...}":    s3Object("PutObject"),
		"GET /api/v1/buckets/{name}/objects/{key...}":    s3Object("GetObject"),
		"DELETE /api/v1/buckets/{name}/objects/{key...}": s3Object("DeleteObject"),
		routeLogin:   nil,
		routeLogout:  nil,
		routeSession: nil,
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
	if pattern == "" || pattern == routeLogin {
		h.mux.ServeHTTP(w, r)
		return
	}
	authz, known := routeAction(pattern)
	if !known {
		writeErr(w, r, resource.Denied("route has no IAM action"))
		return
	}
	if r.Header.Get("Authorization") == "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if _, err := r.Cookie(SessionCookie); err == nil && !h.browserWriteOK(w, r) {
			return
		}
	}
	c, err := h.authenticate(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if authz != nil {
		action, arn := authz(r)
		if err := iam.Check(r.Context(), h.iam, c, action, arn); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	h.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
}

// authenticate takes the bearer console token (the account root, until it is
// retired) or the session cookie.
func (h *handler) authenticate(r *http.Request) (resource.Caller, error) {
	if raw := r.Header.Get("Authorization"); raw != "" {
		const prefix = "Bearer "
		if h.auth == nil || !strings.HasPrefix(raw, prefix) {
			return resource.Caller{}, resource.Unauthenticated("bearer token required")
		}
		return h.auth.Authenticate(r.Context(), raw[len(prefix):])
	}
	ck, err := r.Cookie(SessionCookie)
	if err != nil || ck.Value == "" || h.iam == nil {
		return resource.Caller{}, resource.Unauthenticated("sign in required")
	}
	s, err := h.iam.ValidateSession(r.Context(), ck.Value)
	if err != nil {
		return resource.Caller{}, sessionErr(err)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		want := csrfToken(ck.Value)
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(want)) != 1 {
			return resource.Caller{}, resource.Denied("missing or invalid csrf token")
		}
	}
	return resource.Caller{Account: s.Principal.Account, Subject: "session", Principal: s.Principal.ARN, Root: s.Principal.Root, Ref: s.Principal.Ref}, nil
}

func sessionErr(err error) error {
	var re *resource.Error
	if errors.As(err, &re) {
		return re
	}
	return &resource.Error{Code: resource.CodeUnavailable, Message: "session check unavailable"}
}

type loginBody struct {
	Account  string `json:"account"`
	UserName string `json:"userName"`
	Password string `json:"password"`
	MFACode  string `json:"mfaCode,omitempty"`
}

type sessionBody struct {
	Principal string    `json:"principal"`
	Account   string    `json:"account"`
	Root      bool      `json:"root"`
	ExpiresAt time.Time `json:"expiresAt"`
	CSRFToken string    `json:"csrfToken,omitempty"`
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if h.iam == nil {
		writeErr(w, r, resource.Unimplemented("console sign-in is not configured"))
		return
	}
	if !h.browserWriteOK(w, r) {
		return
	}
	ip := h.clientIP(r)
	if ok, wait := h.logins.take(ip, h.now()); !ok {
		h.log.WarnContext(r.Context(), "console sign-in rate limited", slog.String("source_ip", ip))
		retryAfter(w, wait)
		writeErr(w, r, &resource.Error{Code: resource.CodeResourceExhausted, Message: "too many sign-in attempts; retry later"})
		return
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxLoginBody))
	dec.DisallowUnknownFields()
	var in loginBody
	if err := dec.Decode(&in); err != nil {
		writeErr(w, r, resource.Invalid("body", "malformed sign-in request"))
		return
	}
	account, err := resource.Parse[resource.AccountID](in.Account)
	if err != nil || in.UserName == "" || in.Password == "" || len(in.UserName) > 64 {
		writeErr(w, r, resource.Invalid("body", "account, userName and password are required"))
		return
	}
	s, err := h.iam.Login(r.Context(), iam.LoginRequest{Account: account, UserName: in.UserName, Password: in.Password, MFACode: in.MFACode, SourceIP: ip})
	log := h.log.With(slog.String("account", account.String()), slog.String("user", in.UserName), slog.String("source_ip", ip))
	if err != nil {
		log.WarnContext(r.Context(), "console sign-in failed", slog.String("code", resource.CodeOf(err).String()))
		if iam.IsBusy(err) {
			retryAfter(w, time.Second)
		}
		writeErr(w, r, sessionErr(err))
		return
	}
	log.InfoContext(r.Context(), "console sign-in", slog.String("principal", s.Principal.ARN))
	maxAge := int(time.Until(s.Expires).Seconds())
	csrf := csrfToken(s.Token)
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: s.Token, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: csrf, Path: "/", MaxAge: maxAge, Secure: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, sessionBody{Principal: s.Principal.ARN, Account: s.Principal.Account.String(), Root: s.Principal.Root, ExpiresAt: s.Expires, CSRFToken: csrf})
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(SessionCookie); err == nil && h.iam != nil {
		if err := h.iam.Logout(r.Context(), ck.Value); err != nil {
			writeErr(w, r, sessionErr(err))
			return
		}
	}
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: name == SessionCookie, Secure: true, SameSite: http.SameSiteStrictMode})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) session(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	out := sessionBody{Principal: c.Principal, Account: c.Account.String(), Root: c.Root}
	if ck, err := r.Cookie(SessionCookie); err == nil && h.iam != nil {
		if s, err := h.iam.ValidateSession(r.Context(), ck.Value); err == nil {
			out.ExpiresAt = s.Expires
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
