package router

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var actionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)

// Action names the IAM action of a verified request to an AWS service from its
// headers, form or path only (design.md 3.2.5): X-Amz-Target for JSON
// protocols, the S3 method, path and subresource for S3, the Query Action=,
// and <service>:<METHOD> for any other REST protocol. It reads the body only
// for a Query form and leaves it replayable.
func Action(service sigv4.Service, r *http.Request) (string, error) {
	prefix := string(service) + ":"
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		op := target[strings.LastIndexByte(target, '.')+1:]
		if !actionName.MatchString(op) {
			return "", resource.Invalid("X-Amz-Target", "malformed")
		}
		return prefix + op, nil
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", resource.Invalid("query", "malformed")
	}
	if service == sigv4.ServiceS3 {
		op, err := s3Action(r.Method, r.URL.Path, query)
		if err != nil {
			return "", err
		}
		return prefix + op, nil
	}
	actions := query["Action"]
	form, err := queryForm(r)
	if err != nil {
		return "", err
	}
	actions = append(actions, form["Action"]...)
	switch {
	case len(actions) > 1:
		return "", resource.Invalid("Action", "repeated")
	case len(actions) == 1 && !actionName.MatchString(actions[0]):
		return "", resource.Invalid("Action", "malformed")
	case len(actions) == 1:
		return prefix + actions[0], nil
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return prefix + r.Method, nil
	default:
		return "", resource.Invalid("method", "unsupported")
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

func s3Action(method, path string, query url.Values) (string, error) {
	rest := strings.TrimPrefix(path, "/")
	bucket, key, isObject := strings.Cut(rest, "/")
	if rest == "" {
		if method == http.MethodGet && len(query) == 0 {
			return "ListAllMyBuckets", nil
		}
		return "", resource.Invalid("path", "unsupported S3 request")
	}
	if bucket == "" || isObject && key == "" {
		return "", resource.Invalid("path", "malformed")
	}
	known := s3Subresources()
	sub := ""
	for k := range query {
		if !known[k] {
			continue
		}
		if sub != "" {
			return "", resource.Invalid(k, "more than one S3 subresource")
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
		return "", resource.Invalid("path", "unsupported S3 request")
	}
	if _, versioned := query["versionId"]; versioned && isObject {
		switch op {
		case "GetObject", "DeleteObject", "GetObjectAcl", "PutObjectAcl":
			op = strings.Replace(op, "Object", "ObjectVersion", 1)
		case "GetObjectTagging", "PutObjectTagging", "DeleteObjectTagging":
			op = strings.Replace(op, "ObjectTagging", "ObjectVersionTagging", 1)
		}
	}
	return op, nil
}
