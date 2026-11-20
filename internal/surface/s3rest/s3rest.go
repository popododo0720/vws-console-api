// Package s3rest is the S3 REST entry point of a region without object
// storage. VWS hosts no buckets: S3 requests signed for an AWS region are
// forwarded by internal/router before they reach this package, and a request
// signed for any other region is verified here and answered NotImplemented.
package s3rest

import (
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/popododo0720/vws-lib/errs"
	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/service"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/awscode"
)

// notServed is the message of every signed request this surface refuses.
const notServed = "S3 is served only for AWS regions; this region has no object storage."

// Config wires the object surface.
type Config struct {
	// Verifier checks the signature. Nil refuses every request as unsigned.
	Verifier *sigv4.Verifier
}

// New returns the object handler. It verifies the signature, which reads the
// body to check its payload hash, then answers 501 NotImplemented in S3's
// error shape.
func New(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Verifier == nil {
			writeErr(w, r, sigv4.Reject(sigv4.FailureUnsigned, resource.Unauthenticated("missing signature")), "")
			return
		}
		if _, err := cfg.Verifier.Verify(r); err != nil {
			writeErr(w, r, err, "")
			return
		}
		writeErr(w, r, resource.Unimplemented(notServed), r.URL.Path)
	})
}

// s3Action names the basic S3 action of a path-style request for the error
// metric. The bool is false for a method S3 has no basic action for.
func s3Action(method, p string) (string, bool) {
	rest := strings.TrimPrefix(p, "/")
	_, _, isObject := strings.Cut(rest, "/")
	switch {
	case rest == "":
		if method == http.MethodGet {
			return "s3:ListAllMyBuckets", true
		}
	case isObject:
		switch method {
		case http.MethodPut:
			return "s3:PutObject", true
		case http.MethodGet, http.MethodHead:
			return "s3:GetObject", true
		case http.MethodDelete:
			return "s3:DeleteObject", true
		}
	default:
		switch method {
		case http.MethodPut:
			return "s3:CreateBucket", true
		case http.MethodGet, http.MethodHead:
			return "s3:ListBucket", true
		case http.MethodDelete:
			return "s3:DeleteBucket", true
		}
	}
	return "", false
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
	RequestID         string `xml:"RequestId"`
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, err := w.Write([]byte(xml.Header))
	if err == nil {
		err = xml.NewEncoder(w).Encode(v)
	}
	server.RecordFailure(w, err)
}

// WriteError renders routing failures with the surface's existing error contract.
func WriteError(w http.ResponseWriter, r *http.Request, err error) { writeErr(w, r, err, "") }

func writeErr(w http.ResponseWriter, r *http.Request, err error, resourceName string) {
	action := s3ActionOf(r)
	if rej, ok := sigv4.RejectionOf(err); ok {
		status, body := authError(rej, obs.RequestID(r.Context()))
		obs.M().AWSError(r.Context(), service.Name, action, body.Code)
		writeXML(w, status, body)
		return
	}
	e := resource.AsError(err)
	entry := s3Entry(e)
	if entry.HTTP >= http.StatusInternalServerError {
		server.RecordFailure(w, err)
	}
	obs.M().AWSError(r.Context(), service.Name, action, entry.Code)
	writeXML(w, entry.HTTP, errorXML{
		Code: entry.Code, Message: e.Message, Resource: resourceName, RequestID: obs.RequestID(r.Context()),
	})
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

// s3Entry returns the S3 wire answer for e. The table owns the Code-and-Kind
// policy; a bad access key name is InvalidAccessKeyId, not AccessDenied, which
// only the field can tell apart.
func s3Entry(e *resource.Error) errs.AWSEntry {
	if e.Code == resource.CodeUnauthenticated && e.Field == "AccessKeyId" {
		return errs.AWSEntry{HTTP: http.StatusForbidden, Code: "InvalidAccessKeyId"}
	}
	entry, found := awscode.S3(e.Code, e.Kind)
	if !found {
		return errs.InternalFailure
	}
	return entry
}

// s3ActionOf is the metric label for an S3 request. A path with no basic
// action is "unknown".
func s3ActionOf(r *http.Request) string {
	if action, ok := s3Action(r.Method, r.URL.Path); ok {
		return action
	}
	return "unknown"
}
