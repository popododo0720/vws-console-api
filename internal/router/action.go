package router

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var actionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)

// Action names the IAM actions a verified request to an AWS service needs,
// from its headers, form or path only (design.md 3.2.5). The first is the
// request's own action; any other is a permission it also uses, such as
// s3:GetObject on a copy source. X-Amz-Target names the action only of a
// JSON-protocol call (a POST to / with no Query Action), and S3 never reads
// it: a header the service ignores must not choose what IAM checks. Query
// calls use Action=, S3 its method, path and subresource, and any other REST
// call <service>:<METHOD>. The body is read only for a Query form and stays
// replayable.
func Action(service sigv4.Service, r *http.Request) ([]string, error) {
	prefix := string(service) + ":"
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, resource.Invalid("query", "malformed")
	}
	if service == sigv4.ServiceS3 {
		ops, err := s3Action(r.Method, r.URL.Path, query, r.Header.Get("X-Amz-Copy-Source"))
		if err != nil {
			return nil, err
		}
		for i := range ops {
			ops[i] = prefix + ops[i]
		}
		return ops, nil
	}
	form, err := queryForm(r)
	if err != nil {
		return nil, err
	}
	actions := slices.Concat(query["Action"], form["Action"])
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		op := target[strings.LastIndexByte(target, '.')+1:]
		switch {
		case !actionName.MatchString(op):
			return nil, resource.Invalid("X-Amz-Target", "malformed")
		case len(actions) > 0 || r.Method != http.MethodPost || r.URL.Path != "/":
			return nil, resource.Invalid("X-Amz-Target", "only a JSON-protocol POST to / takes it")
		}
		return []string{prefix + op}, nil
	}
	switch {
	case len(actions) > 1:
		return nil, resource.Invalid("Action", "repeated")
	case len(actions) == 1 && !actionName.MatchString(actions[0]):
		return nil, resource.Invalid("Action", "malformed")
	case len(actions) == 1:
		return []string{prefix + actions[0]}, nil
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return []string{prefix + r.Method}, nil
	default:
		return nil, resource.Invalid("method", "unsupported")
	}
}

func queryForm(r *http.Request) (url.Values, error) {
	media := strings.ToLower(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || !strings.HasPrefix(media, "application/x-www-form-urlencoded") {
		return url.Values{}, nil
	}
	if r.GetBody == nil {
		return nil, resource.Internal(fmt.Errorf("query body is not replayable"))
	}
	body, err := r.GetBody()
	if err != nil {
		return nil, resource.Internal(fmt.Errorf("replay verified body: %w", err))
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, resource.Internal(fmt.Errorf("read verified body: %w", err))
	}
	form, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, resource.Invalid("body", "malformed form")
	}
	return form, nil
}

type s3Op struct{ get, put, del, post string }

// s3Bucket and s3Object follow the S3 action-to-operation mapping
// (docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html).
// A DELETE of a configuration is authorized as its Put action, as S3 does.
func s3Bucket() map[string]s3Op {
	conf := func(get, put string) s3Op { return s3Op{get: get, put: put, del: put} }
	return map[string]s3Op{
		"":                  {get: "ListBucket", put: "CreateBucket", del: "DeleteBucket"},
		"accelerate":        {get: "GetAccelerateConfiguration", put: "PutAccelerateConfiguration"},
		"acl":               {get: "GetBucketAcl", put: "PutBucketAcl"},
		"cors":              conf("GetBucketCORS", "PutBucketCORS"),
		"delete":            {post: "DeleteObject"},
		"encryption":        conf("GetEncryptionConfiguration", "PutEncryptionConfiguration"),
		"lifecycle":         conf("GetLifecycleConfiguration", "PutLifecycleConfiguration"),
		"location":          {get: "GetBucketLocation"},
		"logging":           {get: "GetBucketLogging", put: "PutBucketLogging"},
		"notification":      {get: "GetBucketNotification", put: "PutBucketNotification"},
		"object-lock":       {get: "GetBucketObjectLockConfiguration", put: "PutBucketObjectLockConfiguration"},
		"ownershipControls": conf("GetBucketOwnershipControls", "PutBucketOwnershipControls"),
		"policy":            {get: "GetBucketPolicy", put: "PutBucketPolicy", del: "DeleteBucketPolicy"},
		"policyStatus":      {get: "GetBucketPolicyStatus"},
		"publicAccessBlock": conf("GetBucketPublicAccessBlock", "PutBucketPublicAccessBlock"),
		"replication":       conf("GetReplicationConfiguration", "PutReplicationConfiguration"),
		"requestPayment":    {get: "GetBucketRequestPayment", put: "PutBucketRequestPayment"},
		"tagging":           conf("GetBucketTagging", "PutBucketTagging"),
		"uploads":           {get: "ListBucketMultipartUploads"},
		"versioning":        {get: "GetBucketVersioning", put: "PutBucketVersioning"},
		"versions":          {get: "ListBucketVersions"},
		"website":           {get: "GetBucketWebsite", put: "PutBucketWebsite", del: "DeleteBucketWebsite"},
	}
}

func s3Object() map[string]s3Op {
	return map[string]s3Op{
		"":           {get: "GetObject", put: "PutObject", del: "DeleteObject"},
		"acl":        {get: "GetObjectAcl", put: "PutObjectAcl"},
		"attributes": {get: "GetObjectAttributes"},
		"legal-hold": {get: "GetObjectLegalHold", put: "PutObjectLegalHold"},
		"restore":    {post: "RestoreObject"},
		"retention":  {get: "GetObjectRetention", put: "PutObjectRetention"},
		"tagging":    {get: "GetObjectTagging", put: "PutObjectTagging", del: "DeleteObjectTagging"},
		"torrent":    {get: "GetObjectTorrent"},
		"uploadId":   {get: "ListMultipartUploadParts", put: "PutObject", del: "AbortMultipartUpload", post: "PutObject"},
		"uploads":    {post: "PutObject"},
	}
}

// s3Subresources are the S3 subresources a request may name. One the tables
// above do not map is refused, so a new S3 operation is never authorized as
// a plain read or write of its bucket or object.
func s3Subresources() map[string]bool {
	m := map[string]bool{
		"analytics": true, "intelligent-tiering": true, "inventory": true, "metrics": true, "select": true,
	}
	for k := range s3Bucket() {
		m[k] = true
	}
	for k := range s3Object() {
		m[k] = true
	}
	delete(m, "")
	return m
}

// s3Action also names the read a CopyObject or UploadPartCopy makes of its
// x-amz-copy-source, which S3 authorizes as s3:GetObject (or
// s3:GetObjectVersion) on the source; any other request carrying one is refused.
func s3Action(method, path string, query url.Values, copySource string) ([]string, error) {
	rest := strings.TrimPrefix(path, "/")
	bucket, key, isObject := strings.Cut(rest, "/")
	if rest == "" {
		if method == http.MethodGet && len(query) == 0 {
			return []string{"ListAllMyBuckets"}, nil
		}
		return nil, resource.Invalid("path", "unsupported S3 request")
	}
	if bucket == "" || isObject && key == "" {
		return nil, resource.Invalid("path", "malformed")
	}
	known := s3Subresources()
	sub := ""
	for k := range query {
		if !known[k] {
			continue
		}
		if sub != "" {
			return nil, resource.Invalid(k, "more than one S3 subresource")
		}
		sub = k
	}
	table := s3Bucket()
	if isObject {
		table = s3Object()
	}
	ops, ok := table[sub]
	op := ""
	switch method {
	case http.MethodGet, http.MethodHead:
		op = ops.get
	case http.MethodPut:
		op = ops.put
	case http.MethodDelete:
		op = ops.del
	case http.MethodPost:
		op = ops.post
	}
	if !ok || op == "" {
		return nil, resource.Invalid("path", "unsupported S3 request")
	}
	if _, versioned := query["versionId"]; versioned && isObject {
		switch op {
		case "GetObject", "DeleteObject", "GetObjectAcl", "PutObjectAcl":
			op = strings.Replace(op, "Object", "ObjectVersion", 1)
		case "GetObjectTagging", "PutObjectTagging", "DeleteObjectTagging":
			op = strings.Replace(op, "ObjectTagging", "ObjectVersionTagging", 1)
		}
	}
	if copySource == "" {
		return []string{op}, nil
	}
	if op != "PutObject" || method != http.MethodPut {
		return nil, resource.Invalid("x-amz-copy-source", "not a copy request")
	}
	source, version, _ := strings.Cut(strings.TrimPrefix(copySource, "/"), "?versionId=")
	if b, k, ok := strings.Cut(source, "/"); !ok || b == "" || k == "" {
		return nil, resource.Invalid("x-amz-copy-source", "malformed")
	}
	if version != "" {
		return []string{op, "GetObjectVersion"}, nil
	}
	return []string{op, "GetObject"}, nil
}
