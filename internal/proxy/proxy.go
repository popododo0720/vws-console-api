// Package proxy forwards authorized EC2 requests using isolated AWS credentials.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Account contains the role binding, never source credentials.
type Account struct {
	ID, RoleARN, ExternalID string
	MappingVersion          int64
	Regions                 []string
}

// Accounts resolves the current operator registration on every request.
type Accounts interface {
	Account(context.Context, string, string) (Account, error)
}

type sessionKey struct {
	project        string
	mappingVersion int64
	binding        [32]byte
}

// Proxy accepts forwarding metadata only from the trusted local API process.
type Proxy struct {
	accounts    Accounts
	source      sigv4.Credential
	sts, origin string
	stsRegion   string
	transport   http.RoundTripper
	mu          sync.Mutex
	cache       map[sessionKey]sigv4.Credential
	now         func() time.Time
}

// New requires explicit endpoints; plaintext is allowed only for loopback fakes.
// AssumeRole is signed for stsRegion, the region of the STS endpoint, never
// the EC2 region of a request.
func New(accounts Accounts, source sigv4.Credential, sts, stsRegion, origin string) (*Proxy, error) {
	if accounts == nil || !validCredential(source) {
		return nil, errors.New("proxy: invalid source credentials or accounts")
	}
	if !regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(stsRegion) {
		return nil, errors.New("proxy: invalid STS region")
	}
	for _, raw := range []string{sts, strings.ReplaceAll(origin, "{region}", "us-east-1")} {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/") || (u.Scheme != "https" &&
			(u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback())) {
			return nil, errors.New("proxy: invalid endpoint")
		}
	}
	return &Proxy{
		accounts: accounts, source: source, sts: sts, origin: origin, stsRegion: stsRegion,
		transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
			IdleConnTimeout: 30 * time.Second,
		},
		cache: make(map[sessionKey]sigv4.Credential), now: time.Now,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/internal/v1/aws-accounts/test" {
		p.serveTestConnection(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameterValue")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil && r.Method == http.MethodPost {
		var form url.Values
		form, err = url.ParseQuery(string(body))
		for k, v := range form {
			q[k] = append(q[k], v...)
		}
	}
	account, principal := r.Header.Get("X-Vws-Account"), r.Header.Get("X-Vws-Principal")
	region := r.Header.Get("X-Vws-Target-Region")
	valid := regexp.MustCompile(`^[A-Za-z0-9]+$`)
	if err != nil || r.URL.Path != "/" || (r.Method != http.MethodGet && r.Method != http.MethodPost) ||
		(r.Method == http.MethodGet && len(body) != 0) || len(q["Action"]) != 1 ||
		!allowedAction(q.Get("Action")) ||
		!valid.MatchString(q.Get("Action")) || r.Header.Get("X-Vws-Target-Service") != "ec2" ||
		!regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || principal == "" || len(principal) > 2048 ||
		!regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(region) ||
		r.Header.Get("X-Amz-Region-Set") != "" || r.Header.Get("X-Amz-Target") != "" {
		refuse(w, http.StatusForbidden, "UnauthorizedOperation")
		return
	}
	for k, v := range q {
		if len(v) != 1 || strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			refuse(w, http.StatusForbidden, "UnauthorizedOperation")
			return
		}
	}
	a, err := p.accounts.Account(ctx, account, region)
	if err == nil || a.MappingVersion != 0 || errors.Is(err, store.ErrNotFound) {
		p.mu.Lock()
		for key := range p.cache {
			if key.project == account && key.mappingVersion != a.MappingVersion {
				delete(p.cache, key)
			}
		}
		p.mu.Unlock()
	}
	allowed := false
	for _, v := range a.Regions {
		allowed = allowed || v == region
	}
	if err != nil || !allowed || a.ExternalID == "" ||
		!accountID(a.ID) || !strings.HasPrefix(a.RoleARN, "arn:aws:iam::"+a.ID+":role/") {
		refuse(w, http.StatusForbidden, "AccessDenied")
		return
	}
	cred, err := p.credentials(ctx, account, principal, a)
	if err != nil {
		refuse(w, http.StatusBadGateway, "InternalError")
		return
	}
	target, err := url.Parse(strings.ReplaceAll(p.origin, "{region}", region))
	if err != nil {
		refuse(w, http.StatusBadGateway, "InternalError")
		return
	}
	forward := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header = make(http.Header)
			pr.Out.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			pr.Out.Body = io.NopCloser(bytes.NewReader(body))
			pr.Out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			pr.Out.ContentLength = int64(len(body))
		},
		Transport: signedTransport{
			p: p, credential: cred, region: region, resend: repeatableAction(q.Get("Action"), q.Get("ClientToken")),
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			refuse(w, http.StatusBadGateway, "InternalError")
		},
	}
	forward.ServeHTTP(w, r)
}

func allowedAction(action string) bool {
	switch action {
	case "RunInstances", "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances",
		"CreateSnapshot", "DeleteSnapshot", "CreateTags", "DeleteTags":
		return true
	default:
		return strings.HasPrefix(action, "Describe") && len(action) > len("Describe")
	}
}

func repeatableAction(action, token string) bool {
	switch action {
	case "RunInstances":
		return token != ""
	case "StartInstances", "StopInstances", "TerminateInstances", "DeleteSnapshot", "CreateTags", "DeleteTags":
		return true
	default:
		return strings.HasPrefix(action, "Describe") && len(action) > len("Describe")
	}
}

func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, "<Response><Errors><Error><Code>%s</Code></Error></Errors></Response>", code); err != nil {
		return
	}
}

type signedTransport struct {
	p          *Proxy
	credential sigv4.Credential
	region     string
	resend     bool
}

func (s signedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return s.p.send(r, s.credential, sigv4.ServiceEC2, s.region, s.resend)
}

func (p *Proxy) send(
	r *http.Request, c sigv4.Credential, service sigv4.Service, region string, resend bool,
) (*http.Response, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := sigv4.Sign(r, c, service, region, p.now()); err != nil {
			return nil, errors.New("proxy: signing failed")
		}
		resp, err := p.transport.RoundTrip(r)
		if err == nil && (resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests ||
			attempt == 2 || !resend && resp.StatusCode != http.StatusTooManyRequests) {
			return resp, nil
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				return nil, errors.New("proxy: close response")
			}
		}
		if attempt == 2 || !resend && (resp == nil || resp.StatusCode != http.StatusTooManyRequests) {
			break
		}
		select {
		case <-r.Context().Done():
			return nil, errors.New("proxy: request canceled")
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
		}
		body, err := r.GetBody()
		if err != nil {
			return nil, errors.New("proxy: replay body")
		}
		r.Body = body
	}
	return nil, errors.New("proxy: upstream unavailable")
}

// credentials holds the cache lock only to read and store, never across the
// STS call, so a slow AssumeRole delays no other request.
func (p *Proxy) credentials(ctx context.Context, account, principal string, a Account) (sigv4.Credential, error) {
	// Include the principal and binding so rotation cannot reuse another session's identity.
	key := sessionKey{
		project: account, mappingVersion: a.MappingVersion,
		binding: sha256.Sum256([]byte(a.ID + "\x00" + a.RoleARN + "\x00" + a.ExternalID + "\x00" + principal)),
	}
	p.mu.Lock()
	for k, c := range p.cache {
		if !p.now().Add(5 * time.Minute).Before(c.Expires) {
			delete(p.cache, k)
		}
	}
	c, ok := p.cache[key]
	p.mu.Unlock()
	if ok {
		return c, nil
	}
	c, err := p.assumeRole(ctx, account, principal, a)
	if err != nil {
		return sigv4.Credential{}, err
	}
	p.mu.Lock()
	if len(p.cache) >= 1024 {
		clear(p.cache)
	}
	p.cache[key] = c
	p.mu.Unlock()
	return c, nil
}

func (p *Proxy) assumeRole(ctx context.Context, account, principal string, a Account) (sigv4.Credential, error) {
	return p.assumeRoleRequest(ctx, account, principal, a, false)
}

func (p *Proxy) assumeRoleRequest(
	ctx context.Context, account, principal string, a Account, diagnostic bool,
) (sigv4.Credential, error) {
	hash := sha256.Sum256([]byte(principal))
	form := url.Values{
		"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {a.RoleARN},
		"ExternalId": {a.ExternalID}, "DurationSeconds": {"3600"},
		"RoleSessionName": {fmt.Sprintf("vws-%s-%x", account, hash[:16])},
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, p.sts, strings.NewReader(form.Encode()))
	if err != nil {
		return sigv4.Credential{}, errors.New("proxy: STS request")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.send(r, p.source, sigv4.ServiceSTS, p.stsRegion, true)
	if err != nil {
		return sigv4.Credential{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	closeErr := resp.Body.Close()
	var result struct {
		Credentials struct {
			AccessKeyID string    `xml:"AccessKeyId"`
			Secret      string    `xml:"SecretAccessKey"`
			Token       string    `xml:"SessionToken"`
			Expires     time.Time `xml:"Expiration"`
		} `xml:"AssumeRoleResult>Credentials"`
	}
	if readErr != nil || closeErr != nil || len(data) > 65536 || resp.StatusCode != http.StatusOK ||
		xml.Unmarshal(data, &result) != nil || diagnostic && !validAssumeResponse(data) {
		cause := errors.New("STS response rejected")
		if !diagnostic || readErr != nil || closeErr != nil || resp.StatusCode < 400 ||
			resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			cause = report.Error(ctx, cause)
		}
		return sigv4.Credential{}, &stsError{
			cause:   fmt.Errorf("proxy: %w", cause),
			message: stsMessage(resp.StatusCode, data, false),
		}
	}
	c := sigv4.Credential{
		AccessKey: result.Credentials.AccessKeyID, Secret: result.Credentials.Secret,
		SessionToken: result.Credentials.Token, Expires: result.Credentials.Expires,
	}
	if !validCredential(c) || c.SessionToken == "" || !p.now().Add(5*time.Minute).Before(c.Expires) {
		return sigv4.Credential{}, &stsError{
			cause: errors.New("proxy: STS credentials rejected"), message: "STS returned an unusable response",
		}
	}
	return c, nil
}
