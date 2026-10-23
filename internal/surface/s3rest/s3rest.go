// Package s3rest serves a small path-style object entry point.
// Bucket and object calls finish before the response, which is what S3 clients expect.
package s3rest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Config wires the object surface.
type Config struct {
	Service  *cloud.Service
	Verifier *sigv4.Verifier
	// Authorizer decides each request. Nil denies every request.
	Authorizer iam.Authorizer
}

// New returns the object handler. Paths are /{bucket} and /{bucket}/{key}.
func New(cfg Config) http.Handler {
	h := &handler{svc: cfg.Service, verifier: cfg.Verifier, authz: cfg.Authorizer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.listBuckets)
	mux.HandleFunc("GET /{bucket}", h.listObjects)
	mux.HandleFunc("HEAD /{bucket}", h.headBucket)
	mux.HandleFunc("PUT /{bucket}", h.createBucket)
	mux.HandleFunc("DELETE /{bucket}", h.deleteBucket)
	mux.HandleFunc("PUT /{bucket}/{key...}", h.putObject)
	mux.HandleFunc("GET /{bucket}/{key...}", h.getObject)
	mux.HandleFunc("HEAD /{bucket}/{key...}", h.headObject)
	mux.HandleFunc("DELETE /{bucket}/{key...}", h.deleteObject)
	return h.wrap(mux)
}

type handler struct {
	svc      *cloud.Service
	verifier *sigv4.Verifier
	authz    iam.Authorizer
}

func (h *handler) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.verifier == nil {
			writeErr(w, r, sigv4.Reject(sigv4.FailureUnsigned, resource.Unauthenticated("missing signature")), "")
			return
		}
		caller, err := h.verifier.Verify(r)
		if err != nil {
			writeErr(w, r, err, "")
			return
		}
		if err := unsupportedObjectQuery(r); err != nil {
			writeErr(w, r, err, r.URL.Path)
			return
		}
		if action, arn, ok := s3Action(r.Method, r.URL.Path); ok {
			if err := iam.Check(r.Context(), h.authz, caller, action, arn); err != nil {
				writeErr(w, r, err, r.URL.Path)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(withCaller(r.Context(), caller)))
	})
}

// s3Action names the IAM action and ARN of a routed request. The bool is false
// for a method no route serves; the mux answers that one without acting.
func s3Action(method, p string) (action, arn string, ok bool) {
	rest := strings.TrimPrefix(p, "/")
	bucket, key, isObject := strings.Cut(rest, "/")
	switch {
	case rest == "":
		if method == http.MethodGet {
			return "s3:ListAllMyBuckets", "arn:vws:s3:::*", true
		}
	case isObject:
		arn = "arn:vws:s3:::" + bucket + "/" + key
		switch method {
		case http.MethodPut:
			return "s3:PutObject", arn, true
		case http.MethodGet, http.MethodHead:
			return "s3:GetObject", arn, true
		case http.MethodDelete:
			return "s3:DeleteObject", arn, true
		}
	default:
		arn = "arn:vws:s3:::" + bucket
		switch method {
		case http.MethodPut:
			return "s3:CreateBucket", arn, true
		case http.MethodGet, http.MethodHead:
			return "s3:ListBucket", arn, true
		case http.MethodDelete:
			return "s3:DeleteBucket", arn, true
		}
	}
	return "", "", false
}

func (h *handler) listBuckets(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	q := resource.BucketQuery{}
	if raw := r.URL.Query().Get("max-buckets"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeErr(w, r, resource.Invalid("max-buckets", "malformed"), "")
			return
		}
		q.Page.Size = n
	}
	q.Page.Token = r.URL.Query().Get("continuation-token")
	page, err := h.svc.ListBuckets(r.Context(), c, q)
	if err != nil {
		writeErr(w, r, err, "")
		return
	}
	var buckets []bucketXML
	for _, b := range page.Items {
		buckets = append(buckets, bucketXML{Name: b.Name.String(), CreationDate: b.CreationDate})
	}
	writeXML(w, http.StatusOK, listBucketsXML{
		Owner:                 ownerXML{ID: c.Account.String()},
		Buckets:               bucketList{Items: buckets},
		IsTruncated:           page.NextToken != "",
		NextContinuationToken: page.NextToken,
	})
}

func (h *handler) createBucket(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	name, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		writeErr(w, r, err, r.PathValue("bucket"))
		return
	}
	_, err = h.svc.CreateBucket(r.Context(), c, name)
	if resource.OwnedByCaller(err) && ownedCreateSucceeds(resource.RegionName) {
		err = nil // us-east-1's legacy answer for an owned bucket
	}
	if err != nil {
		writeErr(w, r, err, name.String())
		return
	}
	w.Header().Set("Location", "/"+name.String())
	w.WriteHeader(http.StatusOK)
}

func (h *handler) listObjects(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	bucket, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		writeErr(w, r, err, r.PathValue("bucket"))
		return
	}
	q, v2, err := objectListQuery(r, bucket)
	if err != nil {
		writeErr(w, r, err, bucket.String())
		return
	}
	page, err := h.svc.ListObjects(r.Context(), c, q)
	if err != nil {
		writeErr(w, r, err, bucket.String())
		return
	}
	query := r.URL.Query()
	encode := query.Get("encoding-type") == "url"
	// ListObjects (v1) always returns the owner. V2 returns it on fetch-owner.
	includeOwner := !v2 || query.Get("fetch-owner") == "true"
	contents := make([]objectContentXML, 0, len(page.Objects))
	for _, obj := range page.Objects {
		item := objectContentXML{
			Key:          encodeS3(obj.Key.String(), encode),
			LastModified: obj.LastModified,
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		}
		if includeOwner {
			item.Owner = &ownerXML{ID: obj.OwnerID.String()}
		}
		contents = append(contents, item)
	}
	prefixes := make([]commonPrefixXML, 0, len(page.CommonPrefixes))
	for _, prefix := range page.CommonPrefixes {
		prefixes = append(prefixes, commonPrefixXML{Prefix: encodeS3(prefix, encode)})
	}
	if !v2 {
		writeXML(w, http.StatusOK, listObjectsV1XML{
			Name:           bucket.String(),
			Prefix:         encodeS3(q.Prefix, encode),
			Marker:         encodeS3(q.Token, encode),
			NextMarker:     encodeS3(page.NextToken, encode),
			Delimiter:      encodeS3(q.Delimiter, encode),
			MaxKeys:        q.MaxKeys,
			EncodingType:   query.Get("encoding-type"),
			IsTruncated:    page.NextToken != "",
			Contents:       contents,
			CommonPrefixes: prefixes,
		})
		return
	}
	writeXML(w, http.StatusOK, listObjectsXML{
		Name:                  bucket.String(),
		Prefix:                encodeS3(q.Prefix, encode),
		Delimiter:             encodeS3(q.Delimiter, encode),
		MaxKeys:               q.MaxKeys,
		KeyCount:              len(contents) + len(prefixes),
		EncodingType:          query.Get("encoding-type"),
		ContinuationToken:     query.Get("continuation-token"),
		NextContinuationToken: encodeToken(page.NextToken),
		StartAfter:            encodeS3(q.StartAfter, encode),
		IsTruncated:           page.NextToken != "",
		Contents:              contents,
		CommonPrefixes:        prefixes,
	})
}

// objectListQuery parses ListObjects (v1, no list-type or list-type=1) and
// ListObjectsV2 (list-type=2). The v1 marker is the page position, the same
// thing as the v2 token, so a rolled-up prefix used as a marker skips its keys.
func objectListQuery(r *http.Request, bucket resource.BucketName) (resource.ObjectQuery, bool, error) {
	query := r.URL.Query()
	for key := range query {
		switch strings.ToLower(key) {
		case "list-type", "prefix", "delimiter", "max-keys", "continuation-token", "start-after", "encoding-type", "fetch-owner", "marker":
		default:
			return resource.ObjectQuery{}, false, resource.Unimplemented(key + " is not served")
		}
	}
	var v2 bool
	switch query.Get("list-type") {
	case "", "1":
		for _, key := range []string{"continuation-token", "start-after", "fetch-owner"} {
			if query.Has(key) {
				return resource.ObjectQuery{}, false, resource.Invalid(key, "unsupported without list-type=2")
			}
		}
	case "2":
		if query.Has("marker") {
			return resource.ObjectQuery{}, false, resource.Invalid("marker", "unsupported with list-type=2")
		}
		v2 = true
	default:
		return resource.ObjectQuery{}, false, resource.Invalid("list-type", "unsupported")
	}
	switch query.Get("encoding-type") {
	case "", "url":
	default:
		return resource.ObjectQuery{}, false, resource.Invalid("encoding-type", "unsupported")
	}
	switch query.Get("fetch-owner") {
	case "", "true", "false":
	default:
		return resource.ObjectQuery{}, false, resource.Invalid("fetch-owner", "unsupported")
	}
	token, err := decodeToken(query.Get("continuation-token"))
	if err != nil {
		return resource.ObjectQuery{}, false, err
	}
	if !v2 {
		token = query.Get("marker")
	}
	q := resource.ObjectQuery{
		Bucket:     bucket,
		Prefix:     query.Get("prefix"),
		Delimiter:  query.Get("delimiter"),
		MaxKeys:    1000,
		Token:      token,
		StartAfter: query.Get("start-after"),
	}
	if raw := query.Get("max-keys"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return resource.ObjectQuery{}, false, resource.Invalid("max-keys", "malformed")
		}
		q.MaxKeys = min(n, 1000)
	}
	return q, v2, nil
}

func encodeToken(token string) string {
	if token == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

func decodeToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", resource.Invalid("continuation-token", "malformed")
	}
	return string(raw), nil
}

func encodeS3(s string, urlEncode bool) string {
	if !urlEncode || s == "" {
		return s
	}
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func (h *handler) headBucket(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	name, err := resource.Parse[resource.BucketName](r.PathValue("bucket"))
	if err != nil {
		writeErr(w, r, err, r.PathValue("bucket"))
		return
	}
	if _, err := h.svc.GetBucket(r.Context(), c, name); err != nil {
		writeErr(w, r, err, name.String())
		return
	}
	w.WriteHeader(http.StatusOK)
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
	// If-None-Match: * is a write-once put. An etag list is not applied.
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && ifNoneMatch != "*" {
		writeErr(w, r, resource.Unimplemented("If-None-Match other than *"), r.URL.Path)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, resource.MaxObjectBytes+1))
	if err != nil {
		writeErr(w, r, resource.Internal(err), r.URL.Path)
		return
	}
	if code, message := checkSHA256(r.Header.Get("X-Amz-Checksum-Sha256"), body); code != "" {
		writeXML(w, http.StatusBadRequest, errorXML{
			Code: code, Message: message, Resource: r.URL.Path, RequestID: r.Header.Get("X-Request-Id"),
		})
		return
	}
	obj, err := h.svc.PutObject(r.Context(), c, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: r.Header.Get("Content-Type"), Size: r.ContentLength,
		IfNoneMatch: ifNoneMatch == "*",
	}, bytes.NewReader(body))
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	w.Header().Set("ETag", obj.ETag)
	if requestedSHA256(r) && obj.SHA256 != "" {
		if sum, err := hex.DecodeString(obj.SHA256); err == nil {
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum))
			w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
		}
	}
	w.WriteHeader(http.StatusOK)
}

// requestedSHA256 reports whether a put asked for a SHA256 checksum, either
// by sending one or by naming the algorithm. S3 echoes the checksum only then.
func requestedSHA256(r *http.Request) bool {
	return r.Header.Get("X-Amz-Checksum-Sha256") != "" ||
		strings.EqualFold(r.Header.Get("X-Amz-Sdk-Checksum-Algorithm"), "SHA256") ||
		strings.EqualFold(r.Header.Get("X-Amz-Checksum-Algorithm"), "SHA256")
}

// checkSHA256 compares an x-amz-checksum-sha256 header with the body. It
// returns the S3 error code and message, or "" when the header is absent or
// matches. RGW does not verify this header, so this is the only check.
func checkSHA256(header string, body []byte) (code, message string) {
	if header == "" {
		return "", ""
	}
	want, err := base64.StdEncoding.DecodeString(header)
	if err != nil || len(want) != sha256.Size {
		return "InvalidRequest", "Value for x-amz-checksum-sha256 header is invalid."
	}
	got := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return "BadDigest", "The SHA256 you specified did not match the calculated checksum."
	}
	return "", ""
}

func (h *handler) getObject(w http.ResponseWriter, r *http.Request) {
	meta, body, err := h.openObject(r)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	defer server.Close(w, body)
	writeObjectHeaders(w, r, meta)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, body); err != nil {
		server.RecordFailure(w, fmt.Errorf("copy object body: %w", err))
	}
}

func (h *handler) headObject(w http.ResponseWriter, r *http.Request) {
	meta, body, err := h.openObject(r)
	if err != nil {
		writeErr(w, r, err, r.URL.Path)
		return
	}
	defer server.Close(w, body)
	writeObjectHeaders(w, r, meta)
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.WriteHeader(http.StatusOK)
}

func (h *handler) openObject(r *http.Request) (resource.Object, io.ReadCloser, error) {
	bucket, key, err := objectPath(r)
	if err != nil {
		return resource.Object{}, nil, err
	}
	return h.svc.GetObject(r.Context(), callerFrom(r), resource.GetObjectRequest{Bucket: bucket, Key: key})
}

func writeObjectHeaders(w http.ResponseWriter, r *http.Request, meta resource.Object) {
	if strings.EqualFold(r.Header.Get("X-Amz-Checksum-Mode"), "ENABLED") && meta.SHA256 != "" {
		if sum, err := hex.DecodeString(meta.SHA256); err == nil {
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum))
			w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
		}
	}
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("ETag", meta.ETag)
	if ts, err := time.Parse(time.RFC3339, meta.LastModified); err == nil {
		w.Header().Set("Last-Modified", ts.UTC().Format(http.TimeFormat))
	}
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
	XMLName               struct{}   `xml:"ListAllMyBucketsResult"`
	Owner                 ownerXML   `xml:"Owner"`
	Buckets               bucketList `xml:"Buckets"`
	IsTruncated           bool       `xml:"IsTruncated"`
	NextContinuationToken string     `xml:"NextContinuationToken,omitempty"`
}

type listObjectsXML struct {
	XMLName               struct{}           `xml:"ListBucketResult"`
	Name                  string             `xml:"Name"`
	Prefix                string             `xml:"Prefix"`
	Delimiter             string             `xml:"Delimiter,omitempty"`
	MaxKeys               int                `xml:"MaxKeys"`
	KeyCount              int                `xml:"KeyCount"`
	EncodingType          string             `xml:"EncodingType,omitempty"`
	ContinuationToken     string             `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string             `xml:"NextContinuationToken,omitempty"`
	StartAfter            string             `xml:"StartAfter,omitempty"`
	IsTruncated           bool               `xml:"IsTruncated"`
	Contents              []objectContentXML `xml:"Contents,omitempty"`
	CommonPrefixes        []commonPrefixXML  `xml:"CommonPrefixes,omitempty"`
}

type listObjectsV1XML struct {
	XMLName        struct{}           `xml:"ListBucketResult"`
	Name           string             `xml:"Name"`
	Prefix         string             `xml:"Prefix"`
	Marker         string             `xml:"Marker"`
	NextMarker     string             `xml:"NextMarker,omitempty"`
	Delimiter      string             `xml:"Delimiter,omitempty"`
	MaxKeys        int                `xml:"MaxKeys"`
	EncodingType   string             `xml:"EncodingType,omitempty"`
	IsTruncated    bool               `xml:"IsTruncated"`
	Contents       []objectContentXML `xml:"Contents,omitempty"`
	CommonPrefixes []commonPrefixXML  `xml:"CommonPrefixes,omitempty"`
}

type objectContentXML struct {
	Key          string    `xml:"Key"`
	LastModified string    `xml:"LastModified,omitempty"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
	Owner        *ownerXML `xml:"Owner,omitempty"`
}

type commonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

func unsupportedObjectQuery(r *http.Request) error {
	// Copy stays unimplemented. ObjectService has no copy RPC, and GetObject
	// does not return the payload, so a local copy would write an empty object.
	if r.Header.Get("X-Amz-Copy-Source") != "" {
		return resource.Unimplemented("copy is not served")
	}
	for key := range r.URL.Query() {
		switch strings.ToLower(key) {
		case "tagging", "acl", "policy", "uploadid", "uploads", "versioning", "location", "cors", "lifecycle", "website", "delete", "versions":
			return resource.Unimplemented(key + " is not served")
		}
	}
	return nil
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
	XMLName struct{} `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
	// The detail S3 returns with SignatureDoesNotMatch: what it computed
	// from the request, for the caller to compare with its own.
	AWSAccessKeyID    string `xml:"AWSAccessKeyId,omitempty"`
	StringToSign      string `xml:"StringToSign,omitempty"`
	SignatureProvided string `xml:"SignatureProvided,omitempty"`
	CanonicalRequest  string `xml:"CanonicalRequest,omitempty"`
	Resource          string `xml:"Resource,omitempty"`
	BucketName        string `xml:"BucketName,omitempty"`
	RequestID         string `xml:"RequestId"`
}

// ownedCreateSucceeds reports whether CreateBucket on a bucket the caller
// already owns answers 200 in region. S3 does so only in us-east-1, its
// legacy behavior (which also resets the bucket's ACLs; VWS has none), and
// answers 409 BucketAlreadyOwnedByYou in every other region (#315).
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
//
// VWS has one region, resource.RegionName (vws-1). It is not us-east-1 and
// does not stand in for it, so VWS answers 409.
func ownedCreateSucceeds(region string) bool { return region == "us-east-1" }

// takenBucketMessage is the text S3 sends with BucketAlreadyExists, from the
// error code table of the S3 API Reference (API Version 2006-03-01,
// https://awsdocs.s3.amazonaws.com/S3/latest/s3-api.pdf), as
// resource.BucketOwnedMessage is.
const takenBucketMessage = "The requested bucket name is not available. " +
	"The bucket namespace is shared by all users of the system. Please select a different name and try again."

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, err := w.Write([]byte(xml.Header))
	if err == nil {
		err = xml.NewEncoder(w).Encode(v)
	}
	server.RecordFailure(w, err)
}

func writeErr(w http.ResponseWriter, r *http.Request, err error, resourceName string) {
	if rej, ok := sigv4.RejectionOf(err); ok {
		status, body := authError(rej, r.Header.Get("X-Request-Id"))
		writeXML(w, status, body)
		return
	}
	e := resource.AsError(err)
	if statusOf(e) >= http.StatusInternalServerError {
		server.RecordFailure(w, err)
	}
	out := errorXML{
		Code: s3Code(e), Message: e.Message, Resource: resourceName, RequestID: r.Header.Get("X-Request-Id"),
	}
	if e.Code == resource.CodeAlreadyExists && e.Kind == resource.KindBucket {
		// S3 names the bucket in both create conflicts, with its own text.
		out.BucketName = e.ID
		if !resource.OwnedByCaller(e) {
			out.Message = takenBucketMessage
		}
	}
	writeXML(w, statusOf(e), out)
}

// authError is S3's answer to a SigV4 failure: the code and status from the
// S3 list of error codes, and nothing about which check refused the request
// beyond that code (#245). Only SignatureDoesNotMatch carries detail, and
// only what was computed from the request itself.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html
//
// The message is the text S3 sends where it differs from the list's
// description, as vws-conformance checks it: SignatureDoesNotMatch as the
// SigV4 troubleshooting guide quotes it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-troubleshooting.html),
// AuthorizationHeaderMalformed as the CloudFront guide quotes its start
// (https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-400-bad-request.html)
// without the region or service S3 then names, and RequestTimeTooSkewed and
// InvalidAccessKeyId as S3 sends them.
func authError(rej *sigv4.RejectionError, requestID string) (int, errorXML) {
	out := errorXML{RequestID: requestID}
	status := http.StatusForbidden
	switch rej.Failure {
	case sigv4.FailureMalformed:
		status, out.Code, out.Message = http.StatusBadRequest, "AuthorizationHeaderMalformed",
			"The authorization header is malformed."
	case sigv4.FailureSkewed:
		out.Code, out.Message = "RequestTimeTooSkewed",
			"The difference between the request time and the current time is too large."
	case sigv4.FailureUnknownKey:
		out.Code, out.Message = "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records."
	case sigv4.FailureSignature:
		out.Code, out.Message = "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided. "+
				"Check your key and signing method."
		out.AWSAccessKeyID, out.StringToSign = rej.AccessKeyID, rej.StringToSign
		out.SignatureProvided, out.CanonicalRequest = rej.SignatureProvided, rej.CanonicalRequest
	case sigv4.FailureInvalidToken:
		status, out.Code, out.Message = http.StatusBadRequest, "InvalidToken",
			"The provided token is malformed or otherwise not valid."
	case sigv4.FailureExpiredToken:
		status, out.Code, out.Message = http.StatusBadRequest, "ExpiredToken", "The provided token has expired."
	case sigv4.FailurePayloadHash:
		status, out.Code, out.Message = http.StatusBadRequest, "BadDigest",
			"The Content-MD5 or checksum value that you specified did not match what the server received."
	case sigv4.FailureUnsigned, sigv4.FailureDenied:
		out.Code, out.Message = "AccessDenied", "Access Denied"
	default:
		out.Code, out.Message = "AccessDenied", "Access Denied"
	}
	return status, out
}

func statusOf(e *resource.Error) int {
	switch e.Code {
	case resource.CodeInvalidArgument, resource.CodePayloadTooLarge:
		return http.StatusBadRequest
	case resource.CodeNotFound:
		return http.StatusNotFound
	case resource.CodeAlreadyExists:
		if e.Kind == resource.KindObject {
			// Only a conditional put refuses an existing object.
			return http.StatusPreconditionFailed
		}
		return http.StatusConflict
	case resource.CodeConflict, resource.CodeIdempotencyMismatch:
		return http.StatusConflict
	case resource.CodeUnauthenticated, resource.CodePermissionDenied:
		return http.StatusForbidden
	case resource.CodeResourceExhausted:
		return http.StatusServiceUnavailable
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
		if e.Kind == resource.KindObject {
			return "PreconditionFailed"
		}
		if resource.OwnedByCaller(e) {
			return "BucketAlreadyOwnedByYou"
		}
		return "BucketAlreadyExists"
	case resource.CodeConflict:
		return "BucketNotEmpty"
	case resource.CodeInvalidArgument:
		return "InvalidArgument"
	case resource.CodeUnauthenticated:
		if e.Field == "AccessKeyId" {
			return "InvalidAccessKeyId"
		}
		return "AccessDenied"
	case resource.CodePermissionDenied:
		return "AccessDenied"
	case resource.CodeResourceExhausted:
		return "SlowDown"
	case resource.CodePayloadTooLarge:
		return "EntityTooLarge"
	case resource.CodeUnimplemented:
		return "NotImplemented"
	case resource.CodeUnavailable:
		return "ServiceUnavailable"
	case resource.CodeIdempotencyMismatch:
		return "OperationAborted"
	case resource.CodeInternal, resource.CodeUnspecified:
		return "InternalError"
	default:
		return "InternalError"
	}
}

type callerKey struct{}

func withCaller(ctx context.Context, c resource.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// callerFrom returns the zero caller when none is set. The kernel rejects
// a zero caller as unauthenticated.
func callerFrom(r *http.Request) resource.Caller {
	if c, ok := r.Context().Value(callerKey{}).(resource.Caller); ok {
		return c
	}
	return resource.Caller{}
}
