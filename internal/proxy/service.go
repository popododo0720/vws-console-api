package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// ServiceEndpoint sets the URL template of every service but EC2, with
// {service} and {region} replaced by the signing name and the target region,
// for example https://{service}.{region}.amazonaws.com. Without one those
// services are refused.
func (p *Proxy) ServiceEndpoint(template string) error {
	if err := checkEndpoint(strings.ReplaceAll(template, "{service}", "s3")); err != nil {
		return err
	}
	p.services = template
	return nil
}

// kept are the request headers forwarded besides the x-amz-* ones; each
// changes what the service does, and none carries the caller's credentials.
func kept() []string {
	return []string{
		"Accept", "Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-MD5",
		"Content-Type", "Expires", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since", "Range",
	}
}

// serveService does not interpret the request: the global API verified and
// authorized it, and only its signature is replaced.
func (p *Proxy) serveService(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, resource.MaxObjectBytes))
	if err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameterValue")
		return
	}
	account, principal := r.Header.Get("X-Vws-Account"), r.Header.Get("X-Vws-Principal")
	region, service := r.Header.Get("X-Vws-Target-Region"), r.Header.Get("X-Vws-Target-Service")
	if p.services == "" || !regexp.MustCompile(`^[a-z0-9-]{1,63}$`).MatchString(service) ||
		!regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || principal == "" || len(principal) > 2048 ||
		!regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(region) ||
		r.Header.Get("X-Amz-Region-Set") != "" || presigned(r.URL.RawQuery) || !forwardedMethod(r.Method) {
		refuse(w, http.StatusForbidden, "UnauthorizedOperation")
		return
	}
	cred, ok := p.session(r.Context(), w, account, principal, region)
	if !ok {
		return
	}
	target, err := url.Parse(strings.NewReplacer("{service}", service, "{region}", region).Replace(p.services))
	if err != nil {
		refuse(w, http.StatusBadGateway, "InternalError")
		return
	}
	header, signed := forwardedHeaders(r.Header)
	forward := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header = header.Clone()
			pr.Out.Body = io.NopCloser(bytes.NewReader(body))
			pr.Out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			pr.Out.ContentLength = int64(len(body))
		},
		Transport: signedTransport{
			p: p, credential: cred, service: sigv4.Service(service), region: region,
			resend: r.Method == http.MethodGet || r.Method == http.MethodHead, signed: signed,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			refuse(w, http.StatusBadGateway, "InternalError")
		},
	}
	forward.ServeHTTP(w, r)
}

func forwardedMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

// presigned reports query authentication, which the global API never verifies.
func presigned(raw string) bool {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return true
	}
	for k := range q {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			return true
		}
	}
	return false
}

// forwardedHeaders never copies the caller's signature, date, session token or
// payload hash; it signs every copied x-amz-* header, as AWS requires.
func forwardedHeaders(in http.Header) (http.Header, []string) {
	out := make(http.Header)
	var signed []string
	for name, values := range in {
		low := strings.ToLower(name)
		switch low {
		case "x-amz-date", "x-amz-security-token", "x-amz-content-sha256", "x-amz-region-set":
			continue
		}
		if strings.HasPrefix(low, "x-amz-") {
			out[name] = append([]string(nil), values...)
			signed = append(signed, low)
		}
	}
	for _, name := range kept() {
		if v := in.Values(name); len(v) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), v...)
		}
	}
	return out, signed
}

func checkEndpoint(raw string) error {
	u, err := url.Parse(strings.ReplaceAll(raw, "{region}", "us-east-1"))
	if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || (u.Scheme != "https" &&
		(u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback())) {
		return errors.New("proxy: invalid endpoint")
	}
	return nil
}
