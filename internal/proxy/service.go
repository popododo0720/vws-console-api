package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// ServiceEndpoint sets the URL template of every service but EC2, with
// {service} and {region} replaced by the signing name and the target region,
// using an operator-selected DNS suffix. Without one those
// services are refused.
func (p *Proxy) ServiceEndpoint(template string) error {
	if err := checkEndpoint(strings.ReplaceAll(template, "{service}", "s3")); err != nil {
		return err
	}
	p.services = template
	return nil
}

func (p *Proxy) serveService(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, resource.MaxObjectBytes))
	if err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameterValue")
		return
	}
	account, principal := r.Header.Get("X-Vws-Account"), r.Header.Get("X-Vws-Principal")
	region, service := r.Header.Get("X-Vws-Target-Region"), r.Header.Get("X-Vws-Target-Service")
	costAccount := ""
	if service == "ce" {
		costAccount = r.Header.Get("X-Vws-Aws-Account")
		if !accountID(costAccount) || len(r.Header.Values("X-Vws-Aws-Account")) != 1 ||
			r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" ||
			len(r.Header.Values("X-Amz-Target")) != 1 ||
			r.Header.Get("X-Amz-Target") != "AWSInsightsIndexService.GetCostAndUsage" {
			refuse(w, http.StatusForbidden, "UnauthorizedOperation")
			return
		}
		region = "us-east-1"
	}
	if p.services == "" || !regexp.MustCompile(`^[a-z0-9-]{1,63}$`).MatchString(service) ||
		!regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || !validPrincipal(principal) ||
		len(r.Header.Values("X-Vws-Principal")) != 1 ||
		!regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(region) ||
		!forwardedMethod(r.Method) {
		refuse(w, http.StatusForbidden, "UnauthorizedOperation")
		return
	}
	header := forwardedHeaders(r.Header)
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		body, err = unwrapChunks(body)
		decodedLength := r.Header.Get("X-Amz-Decoded-Content-Length")
		if err != nil || decodedLength != "" && decodedLength != strconv.Itoa(len(body)) {
			refuse(w, http.StatusBadRequest, "InvalidParameterValue")
			return
		}
		encodings := []string{}
		for _, value := range strings.Split(strings.Join(header.Values("Content-Encoding"), ","), ",") {
			if value = strings.TrimSpace(value); value != "" && !strings.EqualFold(value, "aws-chunked") {
				encodings = append(encodings, value)
			}
		}
		header.Del("Content-Encoding")
		if len(encodings) > 0 {
			header.Set("Content-Encoding", strings.Join(encodings, ", "))
		}
		header.Del("X-Amz-Decoded-Content-Length")
	}
	cred, ok := p.accountSession(r.Context(), w, account, principal, region, costAccount)
	if !ok {
		return
	}
	target, err := url.Parse(strings.NewReplacer("{service}", service, "{region}", region).Replace(p.services))
	if err != nil {
		refuse(w, http.StatusBadGateway, "InternalError")
		return
	}
	if service == "s3" {
		host := strings.ToLower(r.Host)
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if bucket, _, found := strings.Cut(host, ".s3."); found {
			target.Host = bucket + "." + target.Host
		}
	}
	p.forward(w, r, target, body, header, cred, service, region,
		service == "ce" || r.Method == http.MethodGet || r.Method == http.MethodHead)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, target *url.URL, body []byte,
	header http.Header, cred sigv4.Credential, service, region string, resend bool,
) {
	signed := make([]string, 0, len(header)+1)
	for name := range header {
		low := strings.ToLower(name)
		if low != "content-type" && low != "x-amz-content-sha256" {
			signed = append(signed, low)
		}
	}
	forward := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header = header.Clone()
			pr.Out.Body = io.NopCloser(bytes.NewReader(body))
			pr.Out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			pr.Out.ContentLength = int64(len(body))
			pr.Out.Header.Set("Content-Length", strconv.Itoa(len(body)))
			pr.Out.TransferEncoding = nil
			pr.Out.URL.RawQuery = r.URL.RawQuery
		},
		Transport: signedTransport{
			p: p, credential: cred, service: sigv4.Service(service), region: region,
			resend: resend,
			signed: append(signed, "content-length"),
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			refuse(w, http.StatusBadGateway, "InternalError")
		},
		ModifyResponse: func(resp *http.Response) error {
			for name := range resp.Header {
				if strings.HasPrefix(strings.ToLower(name), "proxy-") || strings.EqualFold(name, "Expect") {
					resp.Header.Del(name)
				}
			}
			return nil
		},
	}
	forward.ServeHTTP(w, r)
}

func refusedForm(r *http.Request) bool {
	return len(r.Header.Values("X-Amz-Region-Set")) != 0 || presigned(r.URL.RawQuery) ||
		r.Header.Get("X-Amz-Content-Sha256") == "UNSIGNED-PAYLOAD" ||
		strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-ECDSA-")
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

// Keep the original payload hash's presence so the signer can decide whether
// to emit a replacement. Credentials and local identity metadata never pass.
func forwardedHeaders(in http.Header) http.Header {
	out := make(http.Header)
	blocked := make(map[string]bool)
	for _, value := range in.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range in {
		low := strings.ToLower(name)
		if blocked[low] {
			continue
		}
		switch low {
		case "x-amz-date", "x-amz-security-token", "x-amz-region-set":
			continue
		}
		if strings.HasPrefix(low, "x-amz-") {
			out[name] = append([]string(nil), values...)
		}
	}
	for _, name := range []string{
		"Accept", "Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-MD5",
		"Content-Type", "Expires", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since", "Range",
	} {
		if v := in.Values(name); len(v) > 0 && !blocked[strings.ToLower(name)] {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), v...)
		}
	}
	return out
}

// Chunk signatures cannot be reused with the assumed role. Bound both wire
// input and decoded bytes to MaxBody.
func unwrapChunks(wire []byte) ([]byte, error) {
	var body []byte
	for {
		line, rest, ok := bytes.Cut(wire, []byte("\r\n"))
		if !ok {
			break
		}
		size, signature, ok := strings.Cut(string(line), ";chunk-signature=")
		n, err := strconv.ParseUint(size, 16, 64)
		sig, sigErr := hex.DecodeString(signature)
		if !ok || size == "" || strings.ContainsAny(size, "+- ") || err != nil || sigErr != nil || len(sig) != 32 ||
			n > uint64(resource.MaxObjectBytes-len(body)) || n > uint64(len(rest)) {
			break
		}
		end := int(n)
		if len(rest)-end < 2 || string(rest[end:end+2]) != "\r\n" {
			break
		}
		body = append(body, rest[:end]...)
		wire = rest[end+2:]
		if n == 0 {
			if len(wire) == 0 {
				return body, nil
			}
			break
		}
	}
	return nil, errors.New("proxy: invalid chunked body")
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
