// Package s3rest serves a small path-style object entry point.
// Bucket and object calls finish before the response, which is what S3 clients expect.
package s3rest

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Config wires the object surface.
type Config struct {
	Service  *cloud.Service
	Verifier *sigv4.Verifier
}

// New returns the object handler. Paths are /{bucket} and /{bucket}/{key}.
func New(cfg Config) http.Handler {
	h := &handler{svc: cfg.Service, verifier: cfg.Verifier}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.listBuckets)
	mux.HandleFunc("GET /{bucket}", h.unsupportedList)
	mux.HandleFunc("PUT /{bucket}", h.createBucket)
	mux.HandleFunc("DELETE /{bucket}", h.deleteBucket)
	mux.HandleFunc("PUT /{bucket}/{key...}", h.putObject)
	mux.HandleFunc("GET /{bucket}/{key...}", h.getObject)
	mux.HandleFunc("DELETE /{bucket}/{key...}", h.deleteObject)
	return h.wrap(mux)
}

type handler struct {
	svc      *cloud.Service
	verifier *sigv4.Verifier
}

func (h *handler) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.verifier == nil {
			writeErr(w, r, resource.Unauthenticated("missing signature"), "")
			return
		}
		caller, err := h.verifier.Verify(r)
		if err != nil {
			writeErr(w, r, err, "")
			return
		}
		next.ServeHTTP(w, r.WithContext(withCaller(r.Context(), caller)))
	})
}

func (h *handler) listBuckets(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	page, err := h.svc.ListBuckets(r.Context(), c, resource.BucketQuery{})
	if err != nil {
		writeErr(w, r, err, "")
		return
	}
	var buckets []bucketXML
	for _, b := range page.Items {
		buckets = append(buckets, bucketXML{Name: b.Name.String(), CreationDate: b.CreationDate})
	}
	writeXML(w, http.StatusOK, listBucketsXML{
		Owner:   ownerXML{ID: c.Account.String()},
		Buckets: bucketList{Items: buckets},
	})
}

func (h *handler) createBucket(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	name, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		writeErr(w, r, err, r.PathValue("bucket"))
		return
	}
	if _, err := h.svc.CreateBucket(r.Context(), c, name); err != nil {
		writeErr(w, r, err, name.String())
		return
	}
	w.Header().Set("Location", "/"+name.String())
	w.WriteHeader(http.StatusOK)
}

func (h *handler) unsupportedList(w http.ResponseWriter, r *http.Request) {
	writeErr(w, r, resource.Unimplemented("object listing"), r.URL.Path)
}

func (h *handler) deleteBucket(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	name, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		writeErr(w, r, err, r.PathValue("bucket"))
		return
	}
	if err := h.svc.DeleteBucket(r.Context(), c, name); err != nil {
		writeErr(w, r, err, name.String())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) putObject(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	bucket, key, err := objectPath(r)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	obj, err := h.svc.PutObject(r.Context(), c, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: r.Header.Get("Content-Type"), Size: r.ContentLength,
	}, r.Body)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	w.Header().Set("ETag", obj.ETag)
	w.WriteHeader(http.StatusOK)
}

func (h *handler) getObject(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	bucket, key, err := objectPath(r)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	meta, body, err := h.svc.GetObject(r.Context(), c, resource.GetObjectRequest{Bucket: bucket, Key: key})
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	defer func() { _ = body.Close() }()
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("ETag", meta.ETag)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

func (h *handler) deleteObject(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	bucket, key, err := objectPath(r)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	if err := h.svc.DeleteObject(r.Context(), c, bucket, key); err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func objectPath(r *http.Request) (resource.BucketName, resource.ObjectKey, error) {
	bucket, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		return resource.BucketName{}, resource.ObjectKey{}, err
	}
	key, err := resource.Parse[resource.ObjectKey](r.PathValue("key"))
	if err != nil {
		return resource.BucketName{}, resource.ObjectKey{}, err
	}
	return bucket, key, nil
}

type listBucketsXML struct {
	XMLName struct{}   `xml:"ListAllMyBucketsResult"`
	Owner   ownerXML   `xml:"Owner"`
	Buckets bucketList `xml:"Buckets"`
}

type ownerXML struct {
	ID string `xml:"ID"`
}

type bucketList struct {
	Items []bucketXML `xml:"Bucket"`
}

type bucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type errorXML struct {
	XMLName   struct{} `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId"`
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, r *http.Request, err error, resourceName string) {
	e := resource.AsError(err)
	writeXML(w, statusOf(e), errorXML{
		Code: s3Code(e), Message: e.Message, Resource: resourceName, RequestID: r.Header.Get("X-Request-Id"),
	})
}

func statusOf(e *resource.Error) int {
	switch e.Code {
	case resource.CodeInvalidArgument:
		return http.StatusBadRequest
	case resource.CodeNotFound:
		return http.StatusNotFound
	case resource.CodeAlreadyExists, resource.CodeConflict, resource.CodeIdempotencyMismatch:
		return http.StatusConflict
	case resource.CodeUnauthenticated, resource.CodePermissionDenied:
		return http.StatusForbidden
	case resource.CodeResourceExhausted:
		return http.StatusServiceUnavailable
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

func s3Code(e *resource.Error) string {
	switch e.Code {
	case resource.CodeNotFound:
		if e.Kind == resource.KindObject {
			return "NoSuchKey"
		}
		return "NoSuchBucket"
	case resource.CodeAlreadyExists:
		return "BucketAlreadyExists"
	case resource.CodeConflict:
		return "BucketNotEmpty"
	case resource.CodeInvalidArgument:
		return "InvalidArgument"
	case resource.CodeUnauthenticated, resource.CodePermissionDenied:
		return "AccessDenied"
	case resource.CodeResourceExhausted:
		return "SlowDown"
	case resource.CodePayloadTooLarge:
		return "EntityTooLarge"
	case resource.CodeUnimplemented:
		return "NotImplemented"
	case resource.CodeUnavailable:
		return "ServiceUnavailable"
	case resource.CodeIdempotencyMismatch, resource.CodeInternal, resource.CodeUnspecified:
		return "InternalError"
	default:
		return "InternalError"
	}
}

type callerKey struct{}

func withCaller(ctx context.Context, c resource.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func callerFrom(r *http.Request) resource.Caller {
	c, _ := r.Context().Value(callerKey{}).(resource.Caller)
	return c
}
