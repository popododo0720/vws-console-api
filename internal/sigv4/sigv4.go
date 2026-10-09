package sigv4

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
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
)

func (s Service) String() string { return string(s) }

// Credential is the secret half of an access key.
type Credential struct {
	AccessKey string
	Secret    string
	Account   resource.AccountID
}

// Lookup resolves an access key. The bool is false when the key is unknown.
type Lookup func(ctx context.Context, accessKey string) (Credential, bool)

// Verifier checks one service and region.
type Verifier struct {
	Service Service
	Region  string
	Lookup  Lookup
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

// Verify checks r, replaces r.Body with the bytes that were signed, and
// returns the account the access key belongs to.
func (v *Verifier) Verify(r *http.Request) (resource.Caller, error) {
	if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		return resource.Caller{}, resource.Unimplemented("presigned urls are not served")
	}
	body, err := readBody(r.Body, v.MaxBody)
	if err != nil {
		return resource.Caller{}, err
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	stated := r.Header.Get("X-Amz-Content-Sha256")
	switch stated {
	case "":
		return resource.Caller{}, resource.Invalid("X-Amz-Content-Sha256", "required")
	case "UNSIGNED-PAYLOAD":
		payloadHash = stated
	default:
		if !hmac.Equal([]byte(stated), []byte(payloadHash)) {
			return resource.Caller{}, resource.Unauthenticated("payload hash mismatch")
		}
	}

	auth, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return resource.Caller{}, err
	}
	amzDate := r.Header.Get("X-Amz-Date")
	stamp, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return resource.Caller{}, resource.Invalid("X-Amz-Date", "malformed")
	}
	if delta := v.Now().UTC().Sub(stamp); delta > v.Skew || delta < -v.Skew {
		return resource.Caller{}, resource.Unauthenticated("request time is outside the allowed window")
	}
	parts := strings.Split(auth.credential, "/")
	if len(parts) != 5 || parts[1] != stamp.Format("20060102") || parts[2] != v.Region || parts[3] != string(v.Service) || parts[4] != "aws4_request" {
		return resource.Caller{}, resource.Unauthenticated("credential scope rejected")
	}
	if v.Lookup == nil {
		return resource.Caller{}, resource.Unauthenticated("unknown access key")
	}
	cred, ok := v.Lookup(r.Context(), parts[0])
	if !ok || cred.Secret == "" || cred.Account.IsZero() {
		return resource.Caller{}, resource.Unauthenticated("unknown access key")
	}
	canon := canonicalRequest(r, auth.signedHeaders, payloadHash)
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + strings.Join(parts[1:], "/") + "\n" + hexSHA256([]byte(canon))
	mac := hmac.New(sha256.New, signingKey(cred.Secret, parts[1], parts[2], parts[3]))
	_, _ = mac.Write([]byte(stringToSign))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(auth.signature)
	if err != nil || !hmac.Equal(want, got) {
		return resource.Caller{}, resource.Unauthenticated("signature mismatch")
	}
	return resource.Caller{Account: cred.Account, Subject: cred.AccessKey}, nil
}

// Sign sets the date, payload hash, and Authorization header on r.
// It reads and restores the body. Tests and local clients use it.
func Sign(r *http.Request, cred Credential, service Service, region string, now time.Time) error {
	body, err := readBody(r.Body, resource.MaxObjectBytes)
	if err != nil {
		return err
	}
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	amzDate := now.UTC().Format("20060102T150405Z")
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payload)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if r.Header.Get("Content-Type") != "" {
		signed = append(signed, "content-type")
	}
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
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || scheme != "AWS4-HMAC-SHA256" || rest == "" {
		return authorization{}, resource.Unauthenticated("missing signature")
	}
	var out authorization
	for _, item := range strings.Split(rest, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			return authorization{}, resource.Invalid("Authorization", "malformed")
		}
		switch key {
		case "Credential":
			out.credential = val
		case "SignedHeaders":
			out.signedHeaders = strings.Split(val, ";")
		case "Signature":
			out.signature = val
		default:
			return authorization{}, resource.Invalid("Authorization", "unknown field")
		}
	}
	if out.credential == "" || len(out.signedHeaders) == 0 || len(out.signature) != 64 {
		return authorization{}, resource.Invalid("Authorization", "incomplete")
	}
	for _, name := range out.signedHeaders {
		if name == "host" {
			return out, nil
		}
	}
	return authorization{}, resource.Invalid("Authorization", "host is not signed")
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
		return nil, resource.Exhausted("body exceeds the limit")
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

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func sortPairs(p [][2]string) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && (p[j][0] < p[j-1][0] || (p[j][0] == p[j-1][0] && p[j][1] < p[j-1][1])); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
