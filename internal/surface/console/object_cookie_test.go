package console

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// A cookie-session object upload keeps its Content-Type (#224): the PUT
// object route alone skips the JSON Content-Type rule, and still needs the
// console Origin and the X-CSRF-Token header.
func TestCookieObjectUploadKeepsContentType(t *testing.T) {
	e := newLoginEnv(t)
	if err := e.fake.PutInlinePolicy(
		t.Context(), e.account, iam.EntityUser, "bob", "objects",
		`{"Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"*"}]}`,
		backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	bearer := map[string]string{"Authorization": "Bearer tok", "Origin": ""}
	if rec := e.do(t, http.MethodPut, "/api/v1/buckets/b224", "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", rec.Code, rec.Body)
	}
	session, csrf := e.login(t)
	const path = "/api/v1/buckets/b224/objects/logo.png"
	png := map[string]string{"Content-Type": "image/png", CSRFHeader: csrf.Value}

	for name, extra := range map[string]map[string]string{
		"foreign origin": {"Origin": "https://evil.example"},
		"no origin":      {"Origin": ""},
		"no csrf token":  {CSRFHeader: ""},
		"wrong token":    {CSRFHeader: "forged"},
	} {
		h := map[string]string{}
		for k, v := range png {
			h[k] = v
		}
		for k, v := range extra {
			h[k] = v
		}
		rec := e.do(t, http.MethodPut, path, "\x89PNG", h, session)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &body)
		if err != nil || rec.Code != http.StatusForbidden || body.Error.Code != "PermissionDenied" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.do(t, http.MethodGet, path, "", nil, session); rec.Code != http.StatusNotFound {
		t.Fatalf("a refused upload stored an object: %d %s", rec.Code, rec.Body)
	}

	rec := e.do(t, http.MethodPut, path, "\x89PNG", png, session)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin upload: %d %s", rec.Code, rec.Body)
	}
	var put struct {
		ContentType string `json:"contentType"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &put); err != nil || put.ContentType != "image/png" {
		t.Errorf("put contentType %q (%v): %s", put.ContentType, err, rec.Body)
	}
	rec = e.do(t, http.MethodGet, path, "", nil, session)
	var got struct {
		ContentType string `json:"contentType"`
		Body        []byte `json:"body"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if err != nil || rec.Code != http.StatusOK || got.ContentType != "image/png" || string(got.Body) != "\x89PNG" {
		t.Errorf("get %d contentType %q body %q: %s", rec.Code, got.ContentType, got.Body, rec.Body)
	}

	// Every other cookie write still needs a JSON Content-Type.
	vpc := map[string]string{"Content-Type": "text/plain", CSRFHeader: csrf.Value, "Idempotency-Key": "vpc-224"}
	rec = e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, vpc, session)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON cookie write: %d %s", rec.Code, rec.Body)
	}
}
