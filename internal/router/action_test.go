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
		name, service, method, target, contentType, body, want string
	}{
		{"EC2 Query form", "ec2", "POST", "/", form, "Action=DescribeInstances&Version=2016-11-15", "ec2:DescribeInstances"},
		{"EC2 Query URL", "ec2", "GET", "/?Action=RunInstances&Version=2016-11-15", "", "", "ec2:RunInstances"},
		{"STS Query", "sts", "POST", "/", form, "Action=GetCallerIdentity&Version=2011-06-15", "sts:GetCallerIdentity"},
		{"SQS Query", "sqs", "POST", "/", form, "Action=SendMessage&QueueUrl=q", "sqs:SendMessage"},
		{"S3 GetObject", "s3", "GET", "/bucket/key", "", "", "s3:GetObject"},
		{"S3 HeadObject", "s3", "HEAD", "/bucket/dir/key", "", "", "s3:GetObject"},
		{"S3 PutObject", "s3", "PUT", "/bucket/key", "", "bytes", "s3:PutObject"},
		{"S3 DeleteObject", "s3", "DELETE", "/bucket/key", "", "", "s3:DeleteObject"},
		{"S3 ListBuckets", "s3", "GET", "/", "", "", "s3:ListAllMyBuckets"},
		{"S3 ListObjectsV2", "s3", "GET", "/bucket?list-type=2&prefix=a", "", "", "s3:ListBucket"},
		{"S3 CreateBucket", "s3", "PUT", "/bucket", "", "", "s3:CreateBucket"},
		{"S3 GetBucketPolicy", "s3", "GET", "/bucket?policy", "", "", "s3:GetBucketPolicy"},
		{"S3 DeleteBucketCors", "s3", "DELETE", "/bucket?cors", "", "", "s3:PutBucketCORS"},
		{"S3 DeleteObjects", "s3", "POST", "/bucket?delete", "", "<Delete/>", "s3:DeleteObject"},
		{"S3 UploadPart", "s3", "PUT", "/bucket/key?partNumber=1&uploadId=u", "", "part", "s3:PutObject"},
		{"S3 AbortUpload", "s3", "DELETE", "/bucket/key?uploadId=u", "", "", "s3:AbortMultipartUpload"},
		{"S3 GetObjectVersion", "s3", "GET", "/bucket/key?versionId=v", "", "", "s3:GetObjectVersion"},
		{"S3 PutObjectVersionTagging", "s3", "PUT", "/bucket/key?tagging&versionId=v", "", "", "s3:PutObjectVersionTagging"},
		{"S3 GetObject response override", "s3", "GET", "/bucket/key?response-content-type=a", "", "", "s3:GetObject"},
		{"DynamoDB JSON", "dynamodb", "POST", "/", "application/x-amz-json-1.0", `{"Action":"Scan"}`, "dynamodb:PutItem"},
		{"KMS JSON", "kms", "POST", "/", "application/x-amz-json-1.1", "{}", "kms:Decrypt"},
		{"Lambda REST", "lambda", "POST", "/2015-03-31/functions/f/invocations", "application/json", "{}", "lambda:POST"},
		{"Lambda REST read", "lambda", "GET", "/2015-03-31/functions/", "", "", "lambda:GET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, tc.method, tc.target, tc.contentType, tc.body)
			switch tc.service {
			case "dynamodb":
				r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
			case "kms":
				r.Header.Set("X-Amz-Target", "TrentService.Decrypt")
			}
			got, err := router.Action(sigv4.Service(tc.service), r)
			if err != nil || got != tc.want {
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
		name, service, method, target, contentType, body, header string
	}{
		{"repeated Query Action", "sqs", "POST", "/?Action=SendMessage", form, "Action=DeleteQueue", ""},
		{"malformed Query Action", "sqs", "POST", "/", form, "Action=Send%00Message", ""},
		{"malformed X-Amz-Target", "dynamodb", "POST", "/", "application/x-amz-json-1.0", "{}", "DynamoDB_20120810.Put-Item"},
		{"empty X-Amz-Target operation", "dynamodb", "POST", "/", "application/x-amz-json-1.0", "{}", "DynamoDB_20120810."},
		{"unmapped S3 subresource", "s3", "GET", "/bucket?inventory", "", "", ""},
		{"S3 subresource on the wrong method", "s3", "POST", "/bucket?policy", "", "", ""},
		{"two S3 subresources", "s3", "GET", "/bucket/key?acl&tagging", "", "", ""},
		{"S3 empty key", "s3", "GET", "/bucket/", "", "", ""},
		{"S3 root with a query", "s3", "GET", "/?policy", "", "", ""},
		{"REST method", "lambda", "OPTIONS", "/2015-03-31/functions/", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, tc.method, tc.target, tc.contentType, tc.body)
			if tc.header != "" {
				r.Header.Set("X-Amz-Target", tc.header)
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
