package router_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/router"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const form = "application/x-www-form-urlencoded; charset=utf-8"

func TestActionDerivationTable(t *testing.T) {
	for _, tc := range []struct {
		name, service, method, target, contentType, body, header, value, want string
	}{
		{
			"EC2 Query form", "ec2", "POST", "/", form, "Action=DescribeInstances&Version=2016-11-15", "", "",
			"ec2:DescribeInstances",
		},
		{"EC2 Query URL", "ec2", "GET", "/?Action=RunInstances&Version=2016-11-15", "", "", "", "", "ec2:RunInstances"},
		{
			"STS Query", "sts", "POST", "/", form, "Action=GetCallerIdentity&Version=2011-06-15", "", "",
			"sts:GetCallerIdentity",
		},
		{"SQS Query", "sqs", "POST", "/", form, "Action=SendMessage&QueueUrl=q", "", "", "sqs:SendMessage"},
		{"S3 GetObject", "s3", "GET", "/bucket/key", "", "", "", "", "s3:GetObject"},
		{"S3 HeadObject", "s3", "HEAD", "/bucket/dir/key", "", "", "", "", "s3:GetObject"},
		{"S3 PutObject", "s3", "PUT", "/bucket/key", "", "bytes", "", "", "s3:PutObject"},
		{"S3 DeleteObject", "s3", "DELETE", "/bucket/key", "", "", "", "", "s3:DeleteObject"},
		{"S3 ListBuckets", "s3", "GET", "/", "", "", "", "", "s3:ListAllMyBuckets"},
		{"S3 ListObjectsV2", "s3", "GET", "/bucket?list-type=2&prefix=a", "", "", "", "", "s3:ListBucket"},
		{"S3 CreateBucket", "s3", "PUT", "/bucket", "", "", "", "", "s3:CreateBucket"},
		{"S3 GetBucketPolicy", "s3", "GET", "/bucket?policy", "", "", "", "", "s3:GetBucketPolicy"},
		{"S3 DeleteBucketCors", "s3", "DELETE", "/bucket?cors", "", "", "", "", "s3:PutBucketCORS"},
		{"S3 DeleteObjects", "s3", "POST", "/bucket?delete", "", "<Delete/>", "", "", "s3:DeleteObject"},
		{"S3 UploadPart", "s3", "PUT", "/bucket/key?partNumber=1&uploadId=u", "", "part", "", "", "s3:PutObject"},
		{"S3 AbortUpload", "s3", "DELETE", "/bucket/key?uploadId=u", "", "", "", "", "s3:AbortMultipartUpload"},
		{"S3 GetObjectVersion", "s3", "GET", "/bucket/key?versionId=v", "", "", "", "", "s3:GetObjectVersion"},
		{
			"S3 PutObjectVersionTagging", "s3", "PUT", "/bucket/key?tagging&versionId=v", "", "",
			"", "", "s3:PutObjectVersionTagging",
		},
		{"S3 GetObject override", "s3", "GET", "/bucket/key?response-content-type=a", "", "", "", "", "s3:GetObject"},
		{
			"S3 CopyObject", "s3", "PUT", "/bucket/key", "", "",
			"X-Amz-Copy-Source", "/src/a%20b", "s3:PutObject s3:GetObject",
		},
		{
			"S3 UploadPartCopy of a version", "s3", "PUT", "/bucket/key?partNumber=1&uploadId=u", "", "",
			"X-Amz-Copy-Source", "src/k?versionId=v", "s3:PutObject s3:GetObjectVersion",
		},
		{
			"S3 ignores X-Amz-Target", "s3", "DELETE", "/bucket/key", "", "",
			"X-Amz-Target", "x.GetObject", "s3:DeleteObject",
		},
		{
			"DynamoDB JSON", "dynamodb", "POST", "/", "application/x-amz-json-1.0", `{"Action":"Scan"}`,
			"X-Amz-Target", "DynamoDB_20120810.PutItem", "dynamodb:PutItem",
		},
		{
			"KMS JSON", "kms", "POST", "/", "application/x-amz-json-1.1", "{}",
			"X-Amz-Target", "TrentService.Decrypt", "kms:Decrypt",
		},
		{
			"Lambda REST", "lambda", "POST", "/2015-03-31/functions/f/invocations", "application/json", "{}",
			"", "", "lambda:POST",
		},
		{"Lambda REST read", "lambda", "GET", "/2015-03-31/functions/", "", "", "", "", "lambda:GET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, tc.method, tc.target, tc.contentType, tc.body)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			got, err := router.Action(sigv4.Service(tc.service), r)
			if err != nil || strings.Join(got, " ") != tc.want {
				t.Fatalf("Action = %q, %v; want %q", got, err, tc.want)
			}
			if body, err := r.GetBody(); err != nil {
				t.Fatal(err)
			} else if b, _ := io.ReadAll(body); string(b) != tc.body {
				t.Fatalf("body consumed: %q", b)
			}
		})
	}
}

func TestActionRefusesWhatItCannotName(t *testing.T) {
	for _, tc := range []struct {
		name, service, method, target, contentType, body, header, value string
	}{
		{"repeated Query Action", "sqs", "POST", "/?Action=SendMessage", form, "Action=DeleteQueue", "", ""},
		{"malformed Query Action", "sqs", "POST", "/", form, "Action=Send%00Message", "", ""},
		{
			"malformed X-Amz-Target", "dynamodb", "POST", "/", "application/x-amz-json-1.0", "{}",
			"X-Amz-Target", "DynamoDB_20120810.Put-Item",
		},
		{
			"empty X-Amz-Target operation", "dynamodb", "POST", "/", "application/x-amz-json-1.0", "{}",
			"X-Amz-Target", "DynamoDB_20120810.",
		},
		{
			"X-Amz-Target beside a form Action", "sqs", "POST", "/", form, "Action=DeleteQueue",
			"X-Amz-Target", "x.ListQueues",
		},
		{
			"X-Amz-Target beside a query Action", "sqs", "GET", "/?Action=DeleteQueue", "", "",
			"X-Amz-Target", "x.ListQueues",
		},
		{
			"X-Amz-Target on a REST call", "lambda", "POST", "/2015-03-31/functions/f/invocations", "application/json", "{}",
			"X-Amz-Target", "x.GetFunction",
		},
		{"X-Amz-Target on a GET", "dynamodb", "GET", "/", "", "", "X-Amz-Target", "DynamoDB_20120810.GetItem"},
		{"copy source on a non-copy request", "s3", "PUT", "/bucket/key?acl", "", "", "X-Amz-Copy-Source", "/src/k"},
		{"malformed copy source", "s3", "PUT", "/bucket/key", "", "", "X-Amz-Copy-Source", "/src"},
		{"copy source bucket charset", "s3", "PUT", "/bucket/key", "", "", "X-Amz-Copy-Source", "/Src_1/k"},
		{"copy source control character", "s3", "PUT", "/bucket/key", "", "", "X-Amz-Copy-Source", "/src/k%0Ax"},
		{"copy source bad escape", "s3", "PUT", "/bucket/key", "", "", "X-Amz-Copy-Source", "/src/k%zz"},
		{
			"copy source key over 1024 bytes", "s3", "PUT", "/bucket/key", "", "",
			"X-Amz-Copy-Source", "/src/" + strings.Repeat("k", 1025),
		},
		{"copy source other query", "s3", "PUT", "/bucket/key", "", "", "X-Amz-Copy-Source", "/src/k?acl"},
		{
			"copy source version charset", "s3", "PUT", "/bucket/key", "", "",
			"X-Amz-Copy-Source", "/src/k?versionId=a&b=c",
		},
		{"unmapped S3 subresource", "s3", "GET", "/bucket?inventory", "", "", "", ""},
		{"S3 subresource on the wrong method", "s3", "POST", "/bucket?policy", "", "", "", ""},
		{"two S3 subresources", "s3", "GET", "/bucket/key?acl&tagging", "", "", "", ""},
		{"S3 empty key", "s3", "GET", "/bucket/", "", "", "", ""},
		{"S3 root with a query", "s3", "GET", "/?policy", "", "", "", ""},
		{"REST method", "lambda", "OPTIONS", "/2015-03-31/functions/", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, tc.method, tc.target, tc.contentType, tc.body)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			got, err := router.Action(sigv4.Service(tc.service), r)
			if err == nil || resource.AsError(err).Code != resource.CodeInvalidArgument {
				t.Fatalf("Action = %q, %v; want InvalidArgument", got, err)
			}
		})
	}
}

func request(t *testing.T, method, target, contentType, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, "http://vws.test"+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestS3PermissionHeaderBoundaries(t *testing.T) {
	for _, tc := range []struct{ method, path, header string }{
		{"PUT", "/bucket/key", "X-Amz-Grant-Write"},
		{"PUT", "/bucket/key", "X-Amz-Object-Lock-Unknown"},
		{"GET", "/bucket/key", "X-Amz-Acl"},
		{"PUT", "/bucket", "X-Amz-Acl"},
		{"PUT", "/bucket/key?uploadId=u&partNumber=1", "X-Amz-Tagging"},
		{"POST", "/bucket/key?uploadId=u", "X-Amz-Object-Lock-Mode"},
	} {
		r := request(t, tc.method, tc.path, "", "")
		r.Header.Set(tc.header, "value")
		if actions, err := router.Action(sigv4.ServiceS3, r); err == nil {
			t.Errorf("%s %s %s accepted as %v", tc.method, tc.path, tc.header, actions)
		}
	}
	for _, values := range [][]string{{""}, {"public-read", "private"}} {
		r := request(t, "PUT", "/bucket/key", "", "")
		r.Header["X-Amz-Acl"] = values
		if actions, err := router.Action(sigv4.ServiceS3, r); err == nil {
			t.Errorf("ambiguous ACL %v accepted as %v", values, actions)
		}
	}
	for _, host := range []string{".s3.vws.test", "bad_bucket.s3.vws.test", strings.Repeat("b", 64) + ".s3.vws.test"} {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+host+"/key", nil)
		if err != nil {
			t.Fatal(err)
		}
		if actions, err := router.Action(sigv4.ServiceS3, r); err == nil {
			t.Errorf("malformed bucket host %q accepted as %v", host, actions)
		}
	}
	r := request(t, "PUT", "/bucket/key", "", "")
	r.Header.Set("X-Amz-Object-Lock-Mode", "GOVERNANCE")
	r.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", "2030-01-01T00:00:00Z")
	r.Header.Set("X-Amz-Acl", "private")
	r.Header.Set("X-Amz-Grant-Read", `id="owner"`)
	actions, err := router.Action(sigv4.ServiceS3, r)
	if err != nil || len(actions) != 3 {
		t.Fatalf("dependent actions not deduplicated: %v %v", actions, err)
	}
}
