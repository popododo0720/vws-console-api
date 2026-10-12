package sigv4

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestAmbiguousAuthorizationIsRejected covers headers a signer and a
// verifier could read two ways. Each one must fail before the signature is
// compared.
func TestAmbiguousAuthorizationIsRejected(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	v := verifier(c, ServiceEC2, now)
	for name, mutate := range map[string]func(r *http.Request){
		"two Authorization headers": func(r *http.Request) {
			r.Header.Add("Authorization", r.Header.Get("Authorization"))
		},
		"two X-Amz-Date headers": func(r *http.Request) {
			r.Header.Add("X-Amz-Date", r.Header.Get("X-Amz-Date"))
		},
		"repeated Credential field": func(r *http.Request) {
			a := r.Header.Get("Authorization")
			cred := a[strings.Index(a, "Credential="):strings.Index(a, ",")]
			r.Header.Set("Authorization", a+", "+cred)
		},
		"repeated signed header": func(r *http.Request) {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", strings.Replace(a, "SignedHeaders=", "SignedHeaders=host;", 1))
		},
		"missing Authorization": func(r *http.Request) {
			r.Header.Del("Authorization")
		},
		"oversized signature": func(r *http.Request) {
			r.Header.Set("Authorization", r.Header.Get("Authorization")+strings.Repeat("0", 4096))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := signed(t, c, ServiceEC2, now, http.MethodGet, "http://127.0.0.1:8081/?Action=DescribeInstances&Version=2016-11-15", "")
			mutate(r)
			_, err := v.Verify(r)
			if code := resource.CodeOf(err); code != resource.CodeInvalidArgument && code != resource.CodeUnauthenticated {
				t.Fatalf("got %v (%v)", code, err)
			}
		})
	}
}
