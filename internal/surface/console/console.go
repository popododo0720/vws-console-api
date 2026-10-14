// Package console is the JSON API the Next.js console calls.
// The request and response bodies are the resource model. There is no second vocabulary.
package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
)

// Authenticator maps a bearer token to a caller.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (resource.Caller, error)
}

// BearerTokens is a static development authenticator.
type BearerTokens map[string]resource.Caller

// Authenticate returns the caller for token.
func (b BearerTokens) Authenticate(_ context.Context, token string) (resource.Caller, error) {
	c, ok := b[token]
	if !ok {
		return resource.Caller{}, resource.Unauthenticated("unknown token")
	}
	return c, nil
}

// Config wires the console surface.
//
// IAM signs console users in and authorizes every request; without it only
// the bearer Auth works and every request is denied. Auth maps the legacy
// bearer console token to the account root until that token is retired.
type Config struct {
	Service *cloud.Service
	Auth    Authenticator
	IAM     iam.Client
	Logger  *slog.Logger
	// Origins are browser origins allowed besides the console's own host,
	// such as https://console.vws.example.
	Origins []string
	// TrustedProxies are the peers whose X-Forwarded-For is believed when
	// resolving the client address for sign-in limits and logs. Empty means
	// the TCP peer is the client.
	TrustedProxies []netip.Prefix
	// Now is the clock for sign-in rate limits. Nil uses time.Now.
	Now func() time.Time
	// LoginDisabled turns console sign-in off: -iam static. Login and
	// logout answer 501, and GET /api/v1/auth/session reports
	// loginEnabled false, without credentials too, so the UI can skip its
	// sign-in page. The bearer console token keeps working.
	LoginDisabled bool
}

// New returns the console handler.
func New(cfg Config) http.Handler {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	h := &handler{svc: cfg.Service, auth: cfg.Auth, iam: cfg.IAM, log: log, mux: http.NewServeMux(), origins: cfg.Origins, trusted: cfg.TrustedProxies, now: now, logins: newLimiter(), loginOff: cfg.LoginDisabled}
	h.routes(h.mux)
	return http.HandlerFunc(h.gate)
}

func (h *handler) routes(mux *http.ServeMux) {
	handle := func(pattern string, fn http.HandlerFunc) {
		h.patterns = append(h.patterns, pattern)
		mux.HandleFunc(pattern, fn)
	}
	handle(routeLogin, h.login)
	handle(routeLogout, h.logout)
	handle(routeSession, h.session)
	for _, action := range resource.Actions() {
		method, pattern, fn := h.mutation(action)
		handle(method+" "+pattern, fn)
	}
	handle("GET /api/v1/instances", h.listInstances)
	handle("POST /api/v1/instances/stop", h.stopInstances)
	handle("POST /api/v1/instances/start", h.startInstances)
	handle("POST /api/v1/instances/terminate", h.terminateInstances)
	handle("GET /api/v1/instances/{id}", h.getInstance)
	handle("GET /api/v1/operations/{id}", h.getOperation)
	handle("GET /api/v1/subnets", h.listSubnets)
	handle("GET /api/v1/subnets/{id}", h.getSubnet)
	handle("GET /api/v1/vpcs", h.listVpcs)
	handle("GET /api/v1/vpcs/{id}", h.getVpc)
	handle("POST /api/v1/vpcs/{id}/tags", h.tagVpc)
	handle("POST /api/v1/subnets/{id}/tags", h.tagSubnet)
	handle("GET /api/v1/volumes", h.listVolumes)
	handle("GET /api/v1/volumes/{id}", h.getVolume)
	handle("GET /api/v1/images", h.listImages)
	handle("GET /api/v1/instance-types", h.listInstanceTypes)
	handle("GET /api/v1/key-pairs", h.listKeyPairs)
	handle("GET /api/v1/security-groups", h.listSecurityGroups)
	handle("GET /api/v1/addresses", h.listAddresses)
	handle("GET /api/v1/snapshots", h.listSnapshots)
	handle("GET /api/v1/buckets", h.listBuckets)
	handle("PUT /api/v1/buckets/{name}", h.createBucket)
	handle("GET /api/v1/buckets/{name}", h.getBucket)
	handle("DELETE /api/v1/buckets/{name}", h.deleteBucket)
	handle("PUT /api/v1/buckets/{name}/objects/{key...}", h.putObject)
	handle("GET /api/v1/buckets/{name}/objects/{key...}", h.getObject)
	handle("DELETE /api/v1/buckets/{name}/objects/{key...}", h.deleteObject)
}

type handler struct {
	svc      *cloud.Service
	auth     Authenticator
	iam      iam.Client
	loginOff bool
	log      *slog.Logger
	mux      *http.ServeMux
	patterns []string
	origins  []string
	trusted  []netip.Prefix
	now      func() time.Time
	logins   *limiter
}

func (h *handler) mutation(action resource.Action) (string, string, http.HandlerFunc) {
	switch action {
	case resource.ActionRunInstances:
		return http.MethodPost, "/api/v1/instances", h.runInstances
	case resource.ActionStopInstances:
		return http.MethodPost, "/api/v1/instances/{id}/stop", h.stopInstance
	case resource.ActionCreateSubnet:
		return http.MethodPost, "/api/v1/subnets", h.createSubnet
	case resource.ActionCreateVpc:
		return http.MethodPost, "/api/v1/vpcs", h.createVpc
	case resource.ActionDeleteVpc:
		return http.MethodPost, "/api/v1/vpcs/{id}/delete", h.deleteVpc
	case resource.ActionCreateVolume:
		return http.MethodPost, "/api/v1/volumes", h.createVolume
	case resource.ActionAttachVolume:
		return http.MethodPost, "/api/v1/volumes/{id}/attach", h.attachVolume
	case resource.ActionDeleteVolume:
		return http.MethodPost, "/api/v1/volumes/{id}/delete", h.deleteVolume
	case resource.ActionCreateSecurityGroup:
		return http.MethodPost, "/api/v1/security-groups", h.createSecurityGroup
	case resource.ActionAuthorizeSecurityGroupIngress:
		return http.MethodPost, "/api/v1/security-groups/{id}/authorize-ingress", h.authorizeIngress
	case resource.ActionStartInstances:
		return http.MethodPost, "/api/v1/instances/{id}/start", h.startInstance
	case resource.ActionTerminateInstances:
		return http.MethodPost, "/api/v1/instances/{id}/terminate", h.terminateInstance
	case resource.ActionCreateKeyPair:
		return http.MethodPost, "/api/v1/key-pairs", h.createKeyPair
	case resource.ActionDeleteKeyPair:
		return http.MethodPost, "/api/v1/key-pairs/{id}/delete", h.deleteKeyPair
	case resource.ActionDeleteSecurityGroup:
		return http.MethodPost, "/api/v1/security-groups/{id}/delete", h.deleteSecurityGroup
	case resource.ActionDeleteSubnet:
		return http.MethodPost, "/api/v1/subnets/{id}/delete", h.deleteSubnet
	case resource.ActionAllocateAddress:
		return http.MethodPost, "/api/v1/addresses", h.allocateAddress
	case resource.ActionReleaseAddress:
		return http.MethodPost, "/api/v1/addresses/{id}/release", h.releaseAddress
	case resource.ActionCreateSnapshot:
		return http.MethodPost, "/api/v1/snapshots", h.createSnapshot
	case resource.ActionDeleteSnapshot:
		return http.MethodPost, "/api/v1/snapshots/{id}/delete", h.deleteSnapshot
	case resource.ActionAssociateAddress:
		return http.MethodPost, "/api/v1/addresses/{id}/associate", h.associateAddress
	case resource.ActionModifyVolume:
		return http.MethodPost, "/api/v1/volumes/{id}/modify", h.modifyVolume
	case resource.ActionCreateTags:
		return http.MethodPost, "/api/v1/instances/{id}/tags", h.createTags
	case resource.ActionDisassociateAddress:
		return http.MethodPost, "/api/v1/addresses/{id}/disassociate", h.disassociateAddress
	default:
		return http.MethodGet, "/api/v1/unsupported", func(w http.ResponseWriter, r *http.Request) {
			writeErr(w, r, resource.Unimplemented(action.String()))
		}
	}
}

func (h *handler) runInstances(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.RunInstancesRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.RunInstances(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) stopInstance(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.StopInstances(r.Context(), c, token, resource.StopInstancesRequest{IDs: []resource.InstanceID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) createSubnet(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateSubnetRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateSubnet(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) listInstances(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	q, err := instanceQuery(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeInstances(r.Context(), c, q)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *handler) getInstance(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeInstances(r.Context(), c, resource.InstanceQuery{IDs: []resource.InstanceID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(page.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindInstance, id.String()))
		return
	}
	writeJSON(w, http.StatusOK, page.Items[0])
}

func (h *handler) getOperation(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.OperationID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	op, err := h.svc.GetOperation(r.Context(), c, id)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func (h *handler) listSubnets(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeSubnets(r.Context(), c, resource.SubnetQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getSubnet(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SubnetID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeSubnets(r.Context(), c, resource.SubnetQuery{IDs: []resource.SubnetID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(page.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindSubnet, id.String()))
		return
	}
	writeJSON(w, http.StatusOK, page.Items[0])
}

func (h *handler) listBuckets(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.ListBuckets(r.Context(), c, resource.BucketQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) createBucket(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	name, err := resource.Parse[resource.BucketName](r.PathValue("name"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	b, err := h.svc.CreateBucket(r.Context(), c, name)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (h *handler) getBucket(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	name, err := resource.Parse[resource.BucketName](r.PathValue("name"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	b, err := h.svc.GetBucket(r.Context(), c, name)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (h *handler) deleteBucket(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	name, err := resource.Parse[resource.BucketName](r.PathValue("name"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := h.svc.DeleteBucket(r.Context(), c, name); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) putObject(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	req, err := objectRef(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req.ContentType = r.Header.Get("Content-Type")
	req.Size = r.ContentLength
	obj, err := h.svc.PutObject(r.Context(), c, req, r.Body)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (h *handler) getObject(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	ref, err := objectRef(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	meta, rc, err := h.svc.GetObject(r.Context(), c, resource.GetObjectRequest{Bucket: ref.Bucket, Key: ref.Key})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	defer server.Close(w, rc)
	buf, err := io.ReadAll(io.LimitReader(rc, resource.MaxObjectBytes+1))
	if err != nil {
		writeErr(w, r, resource.Internal(err))
		return
	}
	if len(buf) > resource.MaxObjectBytes {
		writeErr(w, r, resource.TooLarge("object exceeds 4 MiB"))
		return
	}
	writeJSON(w, http.StatusOK, struct {
		resource.Object
		Body []byte `json:"body"`
	}{Object: meta, Body: buf})
}

func (h *handler) deleteObject(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	ref, err := objectRef(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := h.svc.DeleteObject(r.Context(), c, ref.Bucket, ref.Key); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) begin(w http.ResponseWriter, r *http.Request) (resource.Caller, resource.ClientToken, bool) {
	c, ok := h.caller(w, r)
	if !ok {
		return resource.Caller{}, resource.ClientToken{}, false
	}
	token, err := resource.Parse[resource.ClientToken](r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeErr(w, r, resource.Invalid("Idempotency-Key", "required"))
		return resource.Caller{}, resource.ClientToken{}, false
	}
	return c, token, true
}

// caller is the identity the gate authenticated and authorized.
func (h *handler) caller(w http.ResponseWriter, r *http.Request) (resource.Caller, bool) {
	c, ok := r.Context().Value(callerKey{}).(resource.Caller)
	if !ok {
		writeErr(w, r, resource.Unauthenticated("sign in required"))
		return resource.Caller{}, false
	}
	return c, true
}

func instanceQuery(r *http.Request) (resource.InstanceQuery, error) {
	var q resource.InstanceQuery
	if raw := r.URL.Query().Get("instanceId"); raw != "" {
		id, err := resource.Parse[resource.InstanceID](raw)
		if err != nil {
			return q, err
		}
		q.IDs = []resource.InstanceID{id}
	}
	if raw := r.URL.Query().Get("state"); raw != "" {
		st, ok := resource.ParseInstanceState(raw)
		if !ok {
			return q, resource.Invalid("state", "unknown")
		}
		q.States = []resource.InstanceState{st}
	}
	page, err := pageRequest(r)
	if err != nil {
		return q, err
	}
	q.Page = page
	return q, nil
}

func pageRequest(r *http.Request) (resource.PageRequest, error) {
	var p resource.PageRequest
	if raw := r.URL.Query().Get("pageSize"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return p, resource.Invalid("pageSize", "malformed")
		}
		p.Size = n
	}
	p.Token = r.URL.Query().Get("pageToken")
	return p, nil
}

func objectRef(r *http.Request) (resource.PutObjectRequest, error) {
	bucket, err := resource.Parse[resource.BucketName](r.PathValue("name"))
	if err != nil {
		return resource.PutObjectRequest{}, err
	}
	key, err := resource.Parse[resource.ObjectKey](r.PathValue("key"))
	if err != nil {
		return resource.PutObjectRequest{}, err
	}
	return resource.PutObjectRequest{Bucket: bucket, Key: key, Size: -1}, nil
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return resource.TooLarge("body exceeds the limit")
		}
		return resource.Invalid("body", "malformed json")
	}
	return nil
}

func writeAccepted[T any](w http.ResponseWriter, acc resource.Accepted[T]) {
	w.Header().Set("Location", "/api/v1/operations/"+acc.Operation.ID.String())
	writeJSON(w, http.StatusAccepted, acc)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	server.RecordFailure(w, enc.Encode(v))
}

type errorBody struct {
	Error   *resource.Error `json:"error"`
	Request string          `json:"requestId,omitempty"`
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	e := resource.AsError(err)
	if statusOf(e.Code) >= http.StatusInternalServerError {
		server.RecordFailure(w, err)
	}
	writeJSON(w, statusOf(e.Code), errorBody{Error: e, Request: r.Header.Get("X-Request-Id")})
}

func statusOf(c resource.Code) int {
	switch c {
	case resource.CodeInvalidArgument:
		return http.StatusBadRequest
	case resource.CodeNotFound:
		return http.StatusNotFound
	case resource.CodeAlreadyExists, resource.CodeConflict, resource.CodeIdempotencyMismatch:
		return http.StatusConflict
	case resource.CodeUnauthenticated:
		return http.StatusUnauthorized
	case resource.CodePermissionDenied:
		return http.StatusForbidden
	case resource.CodeResourceExhausted:
		return http.StatusTooManyRequests
	case resource.CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case resource.CodeUnavailable:
		return http.StatusServiceUnavailable
	case resource.CodeUnimplemented:
		return http.StatusNotImplemented
	case resource.CodeInternal, resource.CodeUnspecified:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// listInstanceTypes is the static machine catalog for the launch screen.
func (h *handler) listInstanceTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.caller(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, resource.Page[resource.InstanceType]{Items: resource.InstanceTypes()})
}

func (h *handler) getVpc(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VpcID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeVpcs(r.Context(), c, resource.VpcQuery{IDs: []resource.VpcID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(page.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindVpc, id.String()))
		return
	}
	writeJSON(w, http.StatusOK, page.Items[0])
}

func (h *handler) getVolume(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeVolumes(r.Context(), c, resource.VolumeQuery{IDs: []resource.VolumeID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(page.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindVolume, id.String()))
		return
	}
	writeJSON(w, http.StatusOK, page.Items[0])
}

// The batch routes take {"instanceIds":[...]} and act on all of them in one
// operation, as StopInstances, StartInstances and TerminateInstances do.

func (h *handler) stopInstances(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.StopInstancesRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.StopInstances(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) startInstances(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.StartInstancesRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.StartInstances(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) terminateInstances(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.TerminateInstancesRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.TerminateInstances(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}
