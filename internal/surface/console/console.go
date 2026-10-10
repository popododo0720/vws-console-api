// Package console is the JSON API the Next.js console calls.
// The request and response bodies are the resource model. There is no second vocabulary.
package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/popododo0720/vws-console-api/internal/cloud"
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
type Config struct {
	Service *cloud.Service
	Auth    Authenticator
}

// New returns the console handler.
func New(cfg Config) http.Handler {
	h := &handler{svc: cfg.Service, auth: cfg.Auth}
	mux := http.NewServeMux()
	for _, action := range resource.Actions() {
		method, pattern, handle := h.mutation(action)
		mux.HandleFunc(method+" "+pattern, handle)
	}
	mux.HandleFunc("GET /api/v1/instances", h.listInstances)
	mux.HandleFunc("GET /api/v1/instances/{id}", h.getInstance)
	mux.HandleFunc("GET /api/v1/operations/{id}", h.getOperation)
	mux.HandleFunc("GET /api/v1/subnets", h.listSubnets)
	mux.HandleFunc("GET /api/v1/subnets/{id}", h.getSubnet)
	mux.HandleFunc("GET /api/v1/vpcs", h.listVpcs)
	mux.HandleFunc("GET /api/v1/volumes", h.listVolumes)
	mux.HandleFunc("GET /api/v1/images", h.listImages)
	mux.HandleFunc("GET /api/v1/buckets", h.listBuckets)
	mux.HandleFunc("PUT /api/v1/buckets/{name}", h.createBucket)
	mux.HandleFunc("GET /api/v1/buckets/{name}", h.getBucket)
	mux.HandleFunc("DELETE /api/v1/buckets/{name}", h.deleteBucket)
	mux.HandleFunc("PUT /api/v1/buckets/{name}/objects/{key...}", h.putObject)
	mux.HandleFunc("GET /api/v1/buckets/{name}/objects/{key...}", h.getObject)
	mux.HandleFunc("DELETE /api/v1/buckets/{name}/objects/{key...}", h.deleteObject)
	return mux
}

type handler struct {
	svc  *cloud.Service
	auth Authenticator
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
	writeAccepted(w, r, acc)
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
	writeAccepted(w, r, acc)
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
	writeAccepted(w, r, acc)
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
	defer func() { _ = rc.Close() }()
	buf, err := io.ReadAll(io.LimitReader(rc, resource.MaxObjectBytes+1))
	if err != nil {
		writeErr(w, r, resource.Internal(err))
		return
	}
	if len(buf) > resource.MaxObjectBytes {
		writeErr(w, r, resource.TooLarge("object exceeds 5 MiB"))
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

func (h *handler) caller(w http.ResponseWriter, r *http.Request) (resource.Caller, bool) {
	if h.auth == nil {
		writeErr(w, r, resource.Unauthenticated("bearer token required"))
		return resource.Caller{}, false
	}
	const prefix = "Bearer "
	raw := r.Header.Get("Authorization")
	if len(raw) < len(prefix) || raw[:len(prefix)] != prefix {
		writeErr(w, r, resource.Unauthenticated("bearer token required"))
		return resource.Caller{}, false
	}
	c, err := h.auth.Authenticate(r.Context(), raw[len(prefix):])
	if err != nil {
		writeErr(w, r, err)
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

func writeAccepted[T any](w http.ResponseWriter, r *http.Request, acc resource.Accepted[T]) {
	w.Header().Set("Location", "/api/v1/operations/"+acc.Operation.ID.String())
	writeJSON(w, http.StatusAccepted, acc)
	_ = r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
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
