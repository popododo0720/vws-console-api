package sigv4

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Service is the name inside the credential scope.
type Service string

// The services this process verifies.
const (
	ServiceEC2 Service = "ec2"
	ServiceS3  Service = "s3"
	ServiceIAM Service = "iam"
	ServiceSTS Service = "sts"
)

// Credential is what a client signs with. Only signing (Sign) and local
// verifiers (Lookup, the static root key, the fake IAM) hold a Secret; the
// verifier itself never sees one. SessionToken is set for temporary (STS)
// credentials and Expires bounds them.
type Credential struct {
	AccessKey    string
	Secret       string
	Account      resource.AccountID
	Principal    string
	Root         bool
	SessionToken string
	Expires      time.Time
}

// AuthRequest is everything needed to check one signature without the
// verifier knowing the secret. It mirrors vws-iam AuthService.Authenticate.
type AuthRequest struct {
	AccessKeyID      string
	Date             string // yyyymmdd from the credential scope
	Region           string
	Service          Service
	CanonicalRequest string
	StringToSign     string
	Signature        string // lowercase hex
	SessionToken     string // X-Amz-Security-Token, empty for long-term keys
	SourceIP         string // client address, for aws:SourceIp and audit
}

// Identity is who a verified signature belongs to.
type Identity struct {
	Account   resource.AccountID
	Principal string
	Root      bool
	Ref       resource.PrincipalRef
}

// ErrUnknownKey is what an Authenticator returns for an access key it does
// not hold.
var ErrUnknownKey = errors.New("unknown access key")

// Failure names the SigV4 check that refused a request. Errors keep the
// code and message every surface already speaks; the failure rides along as
// a *RejectionError cause, so a surface can name its own AWS error for it (S3,
// #245).
type Failure string

// The SigV4 failures.
const (
	// FailureUnsigned is a request without an Authorization header.
	FailureUnsigned Failure = "unsigned"
	// FailureMalformed is an Authorization header or credential scope that
	// cannot be used here: unparsable, another scheme, or a scope for
	// another date, region or service.
	FailureMalformed Failure = "malformed"
	// FailureSkewed is a request time outside the allowed window.
	FailureSkewed Failure = "skewed"
	// FailureUnknownKey is an access key nobody holds.
	FailureUnknownKey Failure = "unknown key"
	// FailureSignature is a signature the key's secret did not produce.
	FailureSignature Failure = "signature"
	// FailureInvalidToken is a session token that is wrong for the key, or
	// one sent with a long-term key.
	FailureInvalidToken Failure = "invalid token"
	// FailureExpiredToken is a session token past its expiry.
	FailureExpiredToken Failure = "expired token"
	// FailurePayloadHash is a body whose hash is not the signed one.
	FailurePayloadHash Failure = "payload hash"
	// FailureDenied is a request this verifier refuses although AWS might
	// not: no usable X-Amz-Date, UNSIGNED-PAYLOAD, an unsigned
	// Content-Type.
	FailureDenied Failure = "denied"
)

// RejectionError is the cause of a SigV4 error. For FailureSignature the
// Verifier fills in what it computed from the request, which S3 returns
// with SignatureDoesNotMatch; never the signature it expected. Error names
// only the failure, so logs never carry request data.
type RejectionError struct {
	Failure           Failure
	AccessKeyID       string
	StringToSign      string
	CanonicalRequest  string
	SignatureProvided string
}

func (r *RejectionError) Error() string { return "sigv4: " + string(r.Failure) }

// RejectionOf returns the RejectionError err carries, if any.
func RejectionOf(err error) (*RejectionError, bool) {
	var r *RejectionError
	ok := errors.As(err, &r)
	return r, ok
}

// Reject marks e as a SigV4 failure. Authenticators use it to say which
// check refused a request.
func Reject(f Failure, e *resource.Error) *resource.Error {
	return e.WithCause(&RejectionError{Failure: f})
}

// SignatureMismatch is the error for a signature the key's secret did not
// produce.
func SignatureMismatch() *resource.Error {
	return Reject(FailureSignature, resource.Unauthenticated("signature mismatch"))
}

// Authenticator checks a signature and names its principal. ErrUnknownKey and
// *resource.Error values reach the caller as they are; any other error means
// the authenticator could not answer.
type Authenticator interface {
	Authenticate(ctx context.Context, req AuthRequest) (Identity, error)
}

// VerifiedBy reports whether secret produced req.Signature. Local
// authenticators that hold the secret use it.
func (req AuthRequest) VerifiedBy(secret string) bool {
	if secret == "" {
		return false
	}
	got, err := hex.DecodeString(req.Signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, signingKey(secret, req.Date, req.Region, string(req.Service)))
	_, _ = mac.Write([]byte(req.StringToSign))
	return hmac.Equal(mac.Sum(nil), got)
}

// CheckSession enforces a temporary credential's token and expiry, and refuses
// a token sent with a long-term key (want empty).
func CheckSession(want, got string, expires, now time.Time) error {
	if want == "" {
		if got != "" {
			return Reject(FailureInvalidToken, resource.Unauthenticated("security token sent with a long-term key"))
		}
		return nil
	}
	if got == "" || !hmac.Equal([]byte(got), []byte(want)) {
		return Reject(FailureInvalidToken, resource.Unauthenticated("the security token included in the request is invalid"))
	}
	if !expires.IsZero() && !now.Before(expires) {
		return Reject(FailureExpiredToken, resource.Unauthenticated("the security token included in the request is expired"))
	}
	return nil
}

// Lookup is a local Authenticator over a key table, for tests and local
// tools. The bool is false when the key is unknown.
type Lookup func(ctx context.Context, accessKey string) (Credential, bool)

// Authenticate implements Authenticator.
func (f Lookup) Authenticate(ctx context.Context, req AuthRequest) (Identity, error) {
	cred, ok := f(ctx, req.AccessKeyID)
	if !ok || cred.Account.IsZero() {
		return Identity{}, ErrUnknownKey
	}
	if err := CheckSession(cred.SessionToken, req.SessionToken, cred.Expires, time.Now()); err != nil {
		return Identity{}, err
	}
	if !req.VerifiedBy(cred.Secret) {
		return Identity{}, SignatureMismatch()
	}
	return Identity{Account: cred.Account, Principal: cred.Principal, Root: cred.Root}, nil
}

// Verifier checks one service and region.
type Verifier struct {
	Service Service
	Region  string
	Auth    Authenticator
	Now     func() time.Time
	Skew    time.Duration
	MaxBody int64
}

// NewVerifier builds a verifier. A nil clock uses time.Now. The default skew
// is five minutes. The default body limit is resource.MaxObjectBytes.
func NewVerifier(v Verifier) *Verifier {
	if v.Now == nil {
		v.Now = time.Now
	}
	if v.Skew == 0 {
		v.Skew = 5 * time.Minute
	}
	if v.MaxBody == 0 {
		v.MaxBody = resource.MaxObjectBytes
	}
	return &v
}

const maxQueryParams = 128

// Verify checks r, replaces r.Body with the bytes that were signed, and
// returns who signed it. The Authenticator checks the signature, so no secret
// reaches this process. A missing payload hash means the hash of the body,
// which is what query clients send. UNSIGNED-PAYLOAD is rejected.
func (v *Verifier) Verify(r *http.Request) (resource.Caller, error) {
	if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		return resource.Caller{}, resource.Unimplemented("presigned urls are not served")
	}
	if err := queryWithinCap(r.URL.RawQuery); err != nil {
		return resource.Caller{}, err
	}
	if len(r.Header.Values("Authorization")) > 1 {
		return resource.Caller{}, Reject(FailureMalformed, resource.Invalid("Authorization", "repeated"))
	}
	auth, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return resource.Caller{}, err
	}
	amzDate := r.Header.Get("X-Amz-Date")
	stamp, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return resource.Caller{}, Reject(FailureDenied, resource.Invalid("X-Amz-Date", "malformed"))
	}
	if delta := v.Now().UTC().Sub(stamp); delta > v.Skew || delta < -v.Skew {
		return resource.Caller{}, Reject(FailureSkewed,
			resource.Unauthenticated("request time is outside the allowed window"))
	}
	parts := strings.Split(auth.credential, "/")
	if len(parts) != 5 || parts[1] != stamp.Format("20060102") || parts[2] != v.Region || parts[3] != string(v.Service) || parts[4] != "aws4_request" {
		return resource.Caller{}, Reject(FailureMalformed, resource.Unauthenticated("credential scope rejected"))
	}
	if v.Auth == nil {
		return resource.Caller{}, unknownKey()
	}
	if r.Header.Get("Content-Type") != "" && !headerSigned(auth.signedHeaders, "content-type") {
		return resource.Caller{}, Reject(FailureDenied, resource.Unauthenticated("content-type is not signed"))
	}

	stated := r.Header.Get("X-Amz-Content-Sha256")
	if stated == "UNSIGNED-PAYLOAD" {
		return resource.Caller{}, Reject(FailureDenied, resource.Unauthenticated("unsigned payload is not accepted"))
	}
	authenticate := func(payloadHash string) (resource.Caller, error) {
		canon := canonicalRequest(r, auth.signedHeaders, payloadHash)
		req := AuthRequest{
			AccessKeyID: parts[0], Date: parts[1], Region: parts[2], Service: Service(parts[3]),
			CanonicalRequest: canon,
			StringToSign:     "AWS4-HMAC-SHA256\n" + amzDate + "\n" + strings.Join(parts[1:], "/") + "\n" + hexSHA256([]byte(canon)),
			Signature:        strings.ToLower(auth.signature),
			SessionToken:     r.Header.Get("X-Amz-Security-Token"),
			SourceIP:         sourceIP(r),
		}
		if _, err := hex.DecodeString(auth.signature); err != nil {
			// No secret produces it, so the authenticator is not asked.
			return resource.Caller{}, mismatch(SignatureMismatch(), req, auth.signature)
		}
		return v.authenticate(r, req, auth.signature)
	}
	// A stated payload hash is part of the signature, so the signer is checked
	// before the body is read and an unknown key costs no body. Without one
	// (query clients) the hash of the body is what was signed.
	var caller resource.Caller
	if stated != "" {
		c, err := authenticate(stated)
		if err != nil {
			return resource.Caller{}, err
		}
		caller = c
	}
	body, err := readBody(r.Body, v.MaxBody)
	if err != nil {
		return resource.Caller{}, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	if stated != "" && !hmac.Equal([]byte(stated), []byte(payloadHash)) {
		return resource.Caller{}, Reject(FailurePayloadHash, resource.Unauthenticated("payload hash mismatch"))
	}
	if v.Service == ServiceEC2 && len(body) > 0 && !headerSigned(auth.signedHeaders, "content-type") {
		return resource.Caller{}, Reject(FailureDenied, resource.Unauthenticated("content-type is not signed"))
	}
	if stated == "" {
		return authenticate(payloadHash)
	}
	return caller, nil
}

// authenticate asks the Authenticator and maps its answer to a caller. An
// Unauthenticated answer that names no failure is a signature mismatch, the
// one check left to the authenticator besides the key and session token.
// sent is the signature as the request carried it.
func (v *Verifier) authenticate(r *http.Request, req AuthRequest, sent string) (resource.Caller, error) {
	id, err := v.Auth.Authenticate(r.Context(), req)
	var re *resource.Error
	switch {
	case errors.Is(err, ErrUnknownKey):
		return resource.Caller{}, unknownKey()
	case errors.As(err, &re):
		rej, tagged := RejectionOf(re)
		switch {
		case re.Code != resource.CodeUnauthenticated:
			return resource.Caller{}, re
		case !tagged && re.Field == "AccessKeyId":
			return resource.Caller{}, Reject(FailureUnknownKey, re)
		case !tagged || rej.Failure == FailureSignature:
			return resource.Caller{}, mismatch(re, req, sent)
		}
		return resource.Caller{}, re
	case err != nil:
		return resource.Caller{}, &resource.Error{Code: resource.CodeUnavailable, Message: "authentication unavailable"}
	}
	if id.Account.IsZero() {
		return resource.Caller{}, unknownKey()
	}
	return resource.Caller{Account: id.Account, Subject: req.AccessKeyID, Principal: id.Principal, Root: id.Root, Ref: id.Ref}, nil
}

// sourceIP is the peer address. X-Forwarded-For is not trusted: console-api
// is reached directly inside the cluster.
func sourceIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func unknownKey() *resource.Error {
	return Reject(FailureUnknownKey, &resource.Error{
		Code: resource.CodeUnauthenticated, Field: "AccessKeyId",
		Message: "The access key ID you provided does not exist in our records.",
	})
}

// mismatch is e for a signature mismatch, carrying what the verifier
// computed from the request: the access key, string to sign and canonical
// request, and the signature as sent. Nothing here depends on a secret.
func mismatch(e *resource.Error, req AuthRequest, sent string) *resource.Error {
	return e.WithCause(&RejectionError{
		Failure: FailureSignature, AccessKeyID: req.AccessKeyID,
		StringToSign: req.StringToSign, CanonicalRequest: req.CanonicalRequest, SignatureProvided: sent,
	})
}

// Sign sets the date, payload hash, and Authorization header on r.
// It reads and restores the body. Tests and local clients use it.
func Sign(r *http.Request, cred Credential, service Service, region string, now time.Time) error {
	return sign(r, cred, service, region, now, true, nil)
}

// SignHeaders is Sign with the named headers added to SignedHeaders. It lets a
// test sign a header the server may rewrite, as an SDK that signs every header
// does.
func SignHeaders(
	r *http.Request, cred Credential, service Service, region string, now time.Time, extra ...string,
) error {
	return sign(r, cred, service, region, now, true, extra)
}

func sign(
	r *http.Request, cred Credential, service Service, region string, now time.Time, payloadHeader bool, extra []string,
) error {
	body, err := readBody(r.Body, resource.MaxObjectBytes)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	amzDate := now.UTC().Format("20060102T150405Z")
	r.Header.Set("X-Amz-Date", amzDate)
	signed := []string{"host", "x-amz-date"}
	if cred.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", cred.SessionToken)
		signed = append(signed, "x-amz-security-token")
	}
	if payloadHeader {
		r.Header.Set("X-Amz-Content-Sha256", payload)
		signed = append(signed, "x-amz-content-sha256")
	} else {
		r.Header.Del("X-Amz-Content-Sha256")
	}
	if r.Header.Get("Content-Type") != "" {
		signed = append(signed, "content-type")
	}
	signed = append(signed, extra...)
	sortStrings(signed)
	scope := amzDate[:8] + "/" + region + "/" + string(service) + "/aws4_request"
	canon := canonicalRequest(r, signed, payload)
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexSHA256([]byte(canon))
	mac := hmac.New(sha256.New, signingKey(cred.Secret, amzDate[:8], region, string(service)))
	_, _ = mac.Write([]byte(stringToSign))
	sig := hex.EncodeToString(mac.Sum(nil))
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cred.AccessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+
		", Signature="+sig)
	return nil
}

type authorization struct {
	credential    string
	signedHeaders []string
	signature     string
}

func parseAuthorization(h string) (authorization, error) {
	if h == "" {
		return authorization{}, Reject(FailureUnsigned, resource.Unauthenticated("missing signature"))
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || scheme != "AWS4-HMAC-SHA256" || rest == "" {
		return authorization{}, Reject(FailureMalformed, resource.Unauthenticated("missing signature"))
	}
	var out authorization
	seen := map[string]bool{}
	for _, item := range strings.Split(rest, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			return authorization{}, Reject(FailureMalformed, resource.Invalid("Authorization", "malformed"))
		}
		if seen[key] {
			return authorization{}, Reject(FailureMalformed, resource.Invalid("Authorization", "repeated field"))
		}
		seen[key] = true
		switch key {
		case "Credential":
			out.credential = val
		case "SignedHeaders":
			out.signedHeaders = strings.Split(val, ";")
		case "Signature":
			out.signature = val
		default:
			return authorization{}, Reject(FailureMalformed, resource.Invalid("Authorization", "unknown field"))
		}
	}
	if out.credential == "" || len(out.signedHeaders) == 0 || len(out.signature) != 64 {
		return authorization{}, Reject(FailureMalformed, resource.Invalid("Authorization", "incomplete"))
	}
	for _, name := range out.signedHeaders {
		if name == "host" {
			return out, nil
		}
	}
	return authorization{}, Reject(FailureMalformed, resource.Invalid("Authorization", "host is not signed"))
}

func canonicalRequest(r *http.Request, signed []string, payloadHash string) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(canonicalPath(r.URL.Path))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(r.URL.RawQuery))
	b.WriteByte('\n')
	names := append([]string(nil), signed...)
	sortStrings(names)
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(headerValue(r, name))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(names, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = awsEncode(part, false)
	}
	return strings.Join(parts, "/")
}

func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var pairs [][2]string
	for _, item := range strings.Split(raw, "&") {
		if item == "" {
			continue
		}
		k, v, _ := strings.Cut(item, "=")
		pairs = append(pairs, [2]string{awsEncode(unescape(k), true), awsEncode(unescape(v), true)})
	}
	sortPairs(pairs)
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p[0])
		b.WriteByte('=')
		b.WriteString(p[1])
	}
	return b.String()
}

func headerValue(r *http.Request, name string) string {
	var vals []string
	if name == "host" {
		vals = []string{r.Host}
	} else {
		vals = r.Header.Values(http.CanonicalHeaderKey(name))
	}
	var parts []string
	for _, v := range vals {
		parts = append(parts, collapse(v))
	}
	return strings.Join(parts, ",")
}

func collapse(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

func signingKey(secret, date, region, service string) []byte {
	kDate := hmacSHA([]byte("AWS4"+secret), date)
	kRegion := hmacSHA(kDate, region)
	kService := hmacSHA(kRegion, service)
	return hmacSHA(kService, "aws4_request")
}

func hmacSHA(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(msg))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readBody(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return []byte{}, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, resource.Internal(err)
	}
	if int64(len(buf)) > max {
		return nil, resource.TooLarge("body exceeds the limit")
	}
	return buf, nil
}

func awsEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) || (!encodeSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte("0123456789ABCDEF"[c>>4])
		b.WriteByte("0123456789ABCDEF"[c&0x0f])
	}
	return b.String()
}

func unreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~'
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			if s[i] == '+' {
				b.WriteByte(' ')
				continue
			}
			b.WriteByte(s[i])
			continue
		}
		h, ok1 := fromHex(s[i+1])
		l, ok2 := fromHex(s[i+2])
		if !ok1 || !ok2 {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(h<<4 | l)
		i += 2
	}
	return b.String()
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func queryWithinCap(raw string) error {
	n := 0
	for _, item := range strings.Split(raw, "&") {
		if item == "" {
			continue
		}
		n++
		if n > maxQueryParams {
			return resource.Invalid("query", "too many parameters")
		}
	}
	return nil
}

func headerSigned(names []string, want string) bool {
	return slices.Contains(names, want)
}

func sortStrings(s []string) { slices.Sort(s) }

func sortPairs(p [][2]string) {
	slices.SortFunc(p, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
}
