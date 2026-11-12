package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func (p *Proxy) serveTestConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal := r.Header.Get("X-Vws-Principal")
	valid := r.Method == http.MethodPost && r.URL.RawQuery == "" &&
		r.Header.Get("Content-Type") == "application/json" &&
		r.Header.Get("X-Vws-Target-Service") == "sts" &&
		r.Header.Get("X-Vws-Target-Region") == "" && principal != "" && len(principal) <= 2048 &&
		strings.IndexFunc(principal, unicode.IsControl) < 0
	for _, key := range []string{"Content-Type", "X-Vws-Principal", "X-Vws-Account", "X-Vws-Target-Service"} {
		valid = valid && len(r.Header.Values(key)) == 1
	}
	var in resource.AWSConnectionRequest
	fields := map[string]*string{"awsAccountId": &in.AccountID, "roleArn": &in.RoleARN, "externalId": &in.ExternalID}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	first, err := dec.Token()
	valid = valid && err == nil && first == json.Delim('{')
	for valid && dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		dst := fields[name]
		if err != nil || !ok || dst == nil || dec.Decode(dst) != nil {
			valid = false
			break
		}
		delete(fields, name)
	}
	last, endErr := dec.Token()
	var extra any
	if !valid || endErr != nil || last != json.Delim('}') || len(fields) != 0 || dec.Decode(&extra) != io.EOF ||
		r.Header.Get("X-Vws-Account") != in.AccountID ||
		resource.ValidateAWSAccount(in.AccountID, in.RoleARN, &in.ExternalID, true) != nil {
		refuse(w, http.StatusBadRequest, "InvalidParameterValue")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cred, err := p.assumeRoleRequest(ctx, in.AccountID, principal,
		Account{RoleARN: in.RoleARN, ExternalID: in.ExternalID}, true)
	steps := resource.AWSConnectionSteps(false, false)
	if err == nil {
		steps = resource.AWSConnectionSteps(true, false)
		message, fault := p.identityMessage(ctx, cred, in.AccountID)
		steps[1].Message = message
		if fault != nil {
			server.RecordFailure(w, report.Error(ctx, fault))
		}
		if steps[1].Message == "AWS account identity matched" {
			steps[1].Result = resource.ConnectionPass
		}
	} else {
		steps[0].Message = "STS unavailable"
		var failure *stsError
		if errors.As(err, &failure) {
			steps[0].Message = failure.message
		}
	}
	w.Header().Set("Content-Type", "application/json")
	server.RecordFailure(w, json.NewEncoder(w).Encode(struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{steps}))
}

func (p *Proxy) identityMessage(ctx context.Context, cred sigv4.Credential, account string) (string, error) {
	form := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, p.sts, strings.NewReader(form.Encode()))
	if err != nil {
		return "STS unavailable", errors.New("STS identity request unavailable")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.send(r, cred, sigv4.ServiceSTS, p.stsRegion, true)
	if err != nil {
		return "STS unavailable", err
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	closeErr := resp.Body.Close()
	var result struct {
		XMLName xml.Name `xml:"GetCallerIdentityResponse"`
		Results []struct {
			Accounts []string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if readErr != nil || closeErr != nil || len(data) > 65536 || resp.StatusCode != http.StatusOK ||
		!decodeSTSDocument(data, &result) || len(result.Results) != 1 || len(result.Results[0].Accounts) != 1 ||
		!accountID(result.Results[0].Accounts[0]) {
		message := stsMessage(resp.StatusCode, data, true)
		if readErr != nil || closeErr != nil || resp.StatusCode < 400 ||
			resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return message, errors.New("STS identity response rejected")
		}
		return message, nil
	}
	if result.Results[0].Accounts[0] != account {
		return "caller identity is in another account", nil
	}
	return "AWS account identity matched", nil
}

func validAssumeResponse(data []byte) bool {
	var result struct {
		XMLName xml.Name `xml:"AssumeRoleResponse"`
		Results []struct {
			Credentials []struct {
				Keys    []string `xml:"AccessKeyId"`
				Secrets []string `xml:"SecretAccessKey"`
				Tokens  []string `xml:"SessionToken"`
				Expires []string `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	if !decodeSTSDocument(data, &result) || len(result.Results) != 1 || len(result.Results[0].Credentials) != 1 {
		return false
	}
	c := result.Results[0].Credentials[0]
	return len(c.Keys) == 1 && len(c.Secrets) == 1 && len(c.Tokens) == 1 && len(c.Expires) == 1
}

func decodeSTSDocument(data []byte, dst any) bool {
	dec := xml.NewDecoder(bytes.NewReader(data))
	seen := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return seen
		}
		if err != nil {
			return false
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if seen || dec.DecodeElement(dst, &v) != nil {
				return false
			}
			seen = true
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return false
			}
		case xml.ProcInst:
			if seen || v.Target != "xml" {
				return false
			}
		case xml.Comment:
		default:
			return false
		}
	}
}

type stsError struct {
	cause   error
	message string
}

func (e *stsError) Error() string { return e.cause.Error() }
func (e *stsError) Unwrap() error { return e.cause }

func stsMessage(status int, data []byte, identity bool) string {
	if status >= 500 || status == http.StatusTooManyRequests {
		return "STS unavailable"
	}
	if status == http.StatusOK {
		return "STS returned an unusable response"
	}
	if identity {
		return "STS rejected the session credentials"
	}
	var failure struct {
		Code string `xml:"Error>Code"`
	}
	if len(data) <= 65536 && xml.Unmarshal(data, &failure) == nil {
		switch failure.Code {
		case "AccessDenied":
			return "AssumeRole was denied; check the role trust policy and ExternalId"
		case "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken":
			return "STS rejected the proxy source credentials"
		}
	}
	return "STS rejected the AssumeRole request"
}
