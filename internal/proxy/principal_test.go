package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrincipalRefusedBeforeSTS(t *testing.T) {
	for _, service := range []string{"s3", "ec2", "sts"} {
		t.Run(service, func(t *testing.T) {
			f := setup(t)
			if err := f.p.ServiceEndpoint("http://127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			for _, principal := range []string{
				"", "with space", "tab\tname", "line\nname", "nul\x00name", "del\x7fname",
				"user;admin", "user&admin", "user%2Fadmin", `user\admin`, "user?admin", "user#admin",
				"user*admin", "nonascii\u00e9", strings.Repeat("x", 2049), "duplicate",
			} {
				for range 2 {
					r := serviceRequest("POST", "/", service, "Action=DescribeInstances")
					want := http.StatusForbidden
					if service == "sts" {
						r = connectionRequest(t.Context(), connectionBody)
						want = http.StatusBadRequest
					}
					r.Header.Set("X-Vws-Principal", principal)
					if principal == "duplicate" {
						r.Header.Add("X-Vws-Principal", "other")
					}
					w := httptest.NewRecorder()
					f.p.ServeHTTP(w, r)
					if w.Code != want || f.stsCalls != 0 || f.originCalls != 0 {
						t.Fatalf("principal=%q status=%d STS=%d origin=%d", principal, w.Code, f.stsCalls, f.originCalls)
					}
				}
			}
		})
	}
}

func TestPrincipalAllowedCharactersAndBounds(t *testing.T) {
	for _, principal := range []string{
		"a", "user_+=,.@-", "arn:vws:iam::123456789012:user/team/alice",
		"arn:vws:sts::123456789012:assumed-role/team/Session_+=,.@-",
		strings.Repeat("a", 2048),
	} {
		t.Run(principal[:1], func(t *testing.T) {
			f := setup(t)
			var calls int
			f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: http.StatusForbidden, Body: http.NoBody, Header: http.Header{}, Request: r,
				}, nil
			})
			for range 2 {
				r := connectionRequest(t.Context(), connectionBody)
				r.Header.Set("X-Vws-Principal", principal)
				w := httptest.NewRecorder()
				f.p.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("allowed principal refused: %d %s", w.Code, w.Body)
				}
			}
			if calls != 2 {
				t.Fatalf("STS calls=%d, want 2", calls)
			}
		})
	}
}
