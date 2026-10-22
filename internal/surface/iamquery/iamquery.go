// Package iamquery serves the IAM and STS Query APIs on one listener. The
// credential scope of the signature (.../iam/... or .../sts/...) picks the
// service, its verifier and its API version. Every action except
// sts:GetCallerIdentity is authorized as iam:<Action> or sts:<Action> before
// it runs; every request, that one included, must be signed.
package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// The Query API versions served.
const (
	IAMVersion = "2010-05-08"
	STSVersion = "2011-06-15"
)

// Config wires the surface. Admin may be nil: then only GetCallerIdentity is
// served and every other action is InvalidAction.
type Config struct {
	Admin      iam.Admin
	Authorizer iam.Authorizer
	IAM        *sigv4.Verifier
	STS        *sigv4.Verifier
}

// New returns the handler.
func New(cfg Config) http.Handler {
	h := &handler{cfg: cfg, actions: actionTable()}
	return http.HandlerFunc(h.serve)
}

type handler struct {
	cfg     Config
	actions map[sigv4.Service]map[string]spec
}

// exchange is one request in flight.
type exchange struct {
	w       http.ResponseWriter
	r       *http.Request
	service sigv4.Service
	caller  resource.Caller
	action  string
}

func (c *exchange) form(k string) string { return c.r.Form.Get(k) }

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	c := &exchange{w: w, r: r, service: scopeService(r.Header.Get("Authorization"))}
	v := h.cfg.IAM
	if c.service == sigv4.ServiceSTS {
		v = h.cfg.STS
	}
	if v == nil || c.service == "" {
		c.fail(resource.Unauthenticated("missing signature"))
		return
	}
	caller, err := v.Verify(r)
	if err != nil {
		c.fail(err)
		return
	}
	c.caller = caller
	if err := r.ParseForm(); err != nil {
		c.fail(resource.Invalid("body", "malformed form"))
		return
	}
	for k, vs := range r.Form {
		if len(vs) > 1 {
			c.fail(resource.Invalid(k, "repeated"))
			return
		}
	}
	want := IAMVersion
	if c.service == sigv4.ServiceSTS {
		want = STSVersion
	}
	if r.Form.Get("Version") != want {
		c.fail(resource.Invalid("Version", "unsupported API version"))
		return
	}
	c.action = r.Form.Get("Action")
	spec, ok := h.actions[c.service][c.action]
	if !ok || (h.cfg.Admin == nil && spec.needsAdmin) {
		c.fail(resource.Unimplemented("Could not find operation " + c.action))
		return
	}
	for k := range r.Form {
		if k == "Action" || k == "Version" || spec.allows(k) {
			continue
		}
		c.fail(resource.Invalid(k, "Parameter "+k+" is not supported"))
		return
	}
	arn := "*"
	if spec.resource != nil {
		arn = spec.resource(h, c)
	}
	if !spec.public {
		if err := iam.Check(r.Context(), h.cfg.Authorizer, c.caller, string(c.service)+":"+c.action, arn); err != nil {
			c.fail(err)
			return
		}
	}
	result, err := spec.run(h, c)
	if err != nil {
		c.fail(err)
		return
	}
	c.ok(result)
}

// scopeService reads the service out of the Credential scope.
func scopeService(auth string) sigv4.Service {
	i := strings.Index(auth, "Credential=")
	if i < 0 {
		return ""
	}
	cred, _, _ := strings.Cut(auth[i+len("Credential="):], ",")
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return ""
	}
	switch s := sigv4.Service(parts[3]); s {
	case sigv4.ServiceIAM, sigv4.ServiceSTS:
		return s
	case sigv4.ServiceEC2, sigv4.ServiceS3:
		return ""
	default:
		return ""
	}
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	return "00000000-0000-0000-0000-000000000000"
}

// ok writes <ActionResponse xmlns><ActionResult>...</ActionResult>
// <ResponseMetadata/></ActionResponse>. A nil result has no Result element.
func (c *exchange) ok(result any) {
	c.w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	c.w.WriteHeader(http.StatusOK)
	_, err := c.w.Write([]byte(xml.Header))
	if err == nil {
		enc := xml.NewEncoder(c.w)
		// No xmlns, like the EC2 and S3 surfaces: SDKs match local names.
		start := xml.StartElement{Name: xml.Name{Local: c.action + "Response"}}
		err = enc.EncodeToken(start)
		if err == nil && result != nil {
			err = enc.EncodeElement(result, xml.StartElement{Name: xml.Name{Local: c.action + "Result"}})
		}
		if err == nil {
			err = enc.EncodeElement(struct {
				RequestID string `xml:"RequestId"`
			}{requestID(c.r)}, xml.StartElement{Name: xml.Name{Local: "ResponseMetadata"}})
		}
		if err == nil {
			err = enc.EncodeToken(start.End())
		}
		if err == nil {
			err = enc.Flush()
		}
	}
	server.RecordFailure(c.w, err)
}

type errorXML struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

func (c *exchange) fail(err error) {
	e := resource.AsError(err)
	status, code := c.wire(e)
	if status >= http.StatusInternalServerError {
		server.RecordFailure(c.w, err)
	}
	typ := "Sender"
	if status >= http.StatusInternalServerError {
		typ = "Receiver"
	}
	c.w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	c.w.WriteHeader(status)
	_, werr := c.w.Write([]byte(xml.Header))
	if werr == nil {
		werr = xml.NewEncoder(c.w).Encode(errorXML{Type: typ, Code: code, Message: e.Message, RequestID: requestID(c.r)})
	}
	server.RecordFailure(c.w, werr)
}

// wire maps a domain error to the IAM/STS status and code.
func (c *exchange) wire(e *resource.Error) (int, string) {
	switch e.Code {
	case resource.CodeUnauthenticated:
		switch {
		case e.Field == "AccessKeyId", strings.Contains(e.Message, "security token included in the request is invalid"):
			return http.StatusForbidden, "InvalidClientTokenId"
		case strings.Contains(e.Message, "expired"):
			return http.StatusForbidden, "ExpiredToken"
		case e.Message == "missing signature":
			return http.StatusForbidden, "MissingAuthenticationToken"
		default:
			return http.StatusForbidden, "SignatureDoesNotMatch"
		}
	case resource.CodePermissionDenied:
		return http.StatusForbidden, "AccessDenied"
	case resource.CodeNotFound:
		return http.StatusNotFound, "NoSuchEntity"
	case resource.CodeAlreadyExists:
		return http.StatusConflict, "EntityAlreadyExists"
	case resource.CodeConflict:
		if e.Field == "UnmodifiableEntity" {
			return http.StatusBadRequest, "UnmodifiableEntity"
		}
		if c.action == "UpdateUser" {
			return http.StatusConflict, "ConcurrentModification"
		}
		return http.StatusConflict, "DeleteConflict"
	case resource.CodeResourceExhausted:
		return http.StatusConflict, "LimitExceeded"
	case resource.CodeInvalidArgument, resource.CodePayloadTooLarge, resource.CodeIdempotencyMismatch:
		switch {
		case e.Field == "PolicyDocument":
			return http.StatusBadRequest, "MalformedPolicyDocument"
		case e.Field == "Password":
			return http.StatusBadRequest, "PasswordPolicyViolation"
		case c.service == sigv4.ServiceSTS, e.Field != "" && e.Field[0] >= 'a' && e.Field[0] <= 'z':
			// Constraint failures on a member (lower-case field) are
			// ValidationError in AWS; STS reports all bad input that way.
			return http.StatusBadRequest, "ValidationError"
		default:
			return http.StatusBadRequest, "InvalidInput"
		}
	case resource.CodeUnimplemented:
		return http.StatusBadRequest, "InvalidAction"
	case resource.CodeUnavailable:
		return http.StatusServiceUnavailable, "ServiceUnavailable"
	case resource.CodeInternal, resource.CodeUnspecified:
		return http.StatusInternalServerError, "ServiceFailure"
	default:
		return http.StatusInternalServerError, "ServiceFailure"
	}
}

// policyDoc URL-encodes a policy document the way IAM returns it.
func policyDoc(doc string) string { return strings.ReplaceAll(url.QueryEscape(doc), "+", "%20") }

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
