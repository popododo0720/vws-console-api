package iamquery

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func keysOf(t *testing.T, f *iam.Fake, account resource.AccountID, user string) int {
	t.Helper()
	ks, err := f.ListAccessKeys(t.Context(), account, user, backendtest.UserGrant(t.Context(), t, f, account, user))
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

// #314 bundle 2: an access key call acts only on the user the caller was
// authorized on. When the user moves to a denied path between the
// authorization and the call, the answer is 409 ConcurrentModification: no
// key is created or deleted and none is listed. Without the move the same
// requests succeed, so the policy allows them.
func TestAccessKeyCallsActOnTheAuthorizedARN(t *testing.T) {
	for _, tc := range []struct {
		name      string
		form      func(key string) url.Values
		user      string
		unchanged func(t *testing.T, f *iam.Fake, account resource.AccountID, body string)
	}{
		{
			"CreateAccessKey",
			func(string) url.Values { return url.Values{"Action": {"CreateAccessKey"}, "UserName": {"dave"}} },
			"dave", func(t *testing.T, f *iam.Fake, account resource.AccountID, _ string) {
				t.Helper()
				if n := keysOf(t, f, account, "dave"); n != 0 {
					t.Errorf("dave has %d keys", n)
				}
			},
		},
		{
			"ListAccessKeys",
			func(string) url.Values { return url.Values{"Action": {"ListAccessKeys"}, "UserName": {"erin"}} },
			"erin", func(t *testing.T, _ *iam.Fake, _ resource.AccountID, body string) {
				t.Helper()
				if regexp.MustCompile(`AKIA[A-Z2-7]{16}`).MatchString(body) {
					t.Errorf("a key was listed: %s", body)
				}
			},
		},
		{
			"DeleteAccessKey",
			func(key string) url.Values {
				return url.Values{"Action": {"DeleteAccessKey"}, "UserName": {"erin"}, "AccessKeyId": {key}}
			},
			"erin", func(t *testing.T, f *iam.Fake, account resource.AccountID, _ string) {
				t.Helper()
				if n := keysOf(t, f, account, "erin"); n != 1 {
					t.Errorf("erin has %d keys, want the 1 she had", n)
				}
			},
		},
	} {
		for _, moved := range []bool{false, true} {
			name := tc.name + "/not moved"
			var mover *movingAdmin
			if moved {
				name = tc.name + "/moved after authorization"
				mover = &movingAdmin{tb: t, user: tc.user}
			}
			t.Run(name, func(t *testing.T) {
				h, f, account, bob := authorizedPrincipalHarness(t, mover)
				k, err := f.CreateAccessKey(t.Context(), account, "erin", backendtest.UserGrant(t.Context(), t, f, account, "erin"))
				if err != nil {
					t.Fatal(err)
				}
				res := call(t, h, bob, sigv4.ServiceIAM, tc.form(k.AccessKeyID))
				if !moved {
					has(t, res, http.StatusOK)
					return
				}
				has(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
				tc.unchanged(t, f, account, res.Body.String())
			})
		}
	}
}

// #314 bundle 2: ListAccessKeys pages with Marker and MaxItems as AWS does,
// takes no PathPrefix, and DeleteAccessKey checks the AccessKeyId pattern.
func TestAccessKeyPagingAndValidation(t *testing.T) {
	h, f, account, bob := authorizedPrincipalHarness(t, nil)
	k1, err := f.CreateAccessKey(t.Context(), account, "carol", backendtest.UserGrant(t.Context(), t, f, account, "carol"))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := f.CreateAccessKey(t.Context(), account, "carol", backendtest.UserGrant(t.Context(), t, f, account, "carol"))
	if err != nil {
		t.Fatal(err)
	}
	first, second := k1.AccessKeyID, k2.AccessKeyID
	if second < first {
		first, second = second, first
	}
	list := func(kv ...string) url.Values {
		v := url.Values{"Action": {"ListAccessKeys"}, "UserName": {"carol"}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	res := call(t, h, bob, sigv4.ServiceIAM, list("MaxItems", "1"))
	has(t, res, http.StatusOK, "<AccessKeyId>"+first+"</AccessKeyId>", "<IsTruncated>true</IsTruncated>",
		"<Marker>", "<UserName>carol</UserName>", "<Status>Active</Status>")
	marker := regexp.MustCompile(`<Marker>([^<]+)</Marker>`).FindStringSubmatch(res.Body.String())
	if marker == nil {
		t.Errorf("no marker: %s", res.Body.String())
	} else {
		res = call(t, h, bob, sigv4.ServiceIAM, list("MaxItems", "1", "Marker", marker[1]))
		has(t, res, http.StatusOK, "<AccessKeyId>"+second+"</AccessKeyId>", "<IsTruncated>false</IsTruncated>")
		if strings.Contains(res.Body.String(), first) {
			t.Errorf("page 2 repeats %s: %s", first, res.Body.String())
		}
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, list()), http.StatusOK,
		"<AccessKeyId>"+first+"</AccessKeyId>", "<AccessKeyId>"+second+"</AccessKeyId>",
		"<IsTruncated>false</IsTruncated>")
	has(t, call(t, h, bob, sigv4.ServiceIAM, list("MaxItems", "0")), http.StatusBadRequest,
		"<Code>ValidationError</Code>")
	has(t, call(t, h, bob, sigv4.ServiceIAM, list("PathPrefix", "/")), http.StatusBadRequest)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"CreateAccessKey"}, "UserName": {"carol"}}),
		http.StatusConflict, "<Code>LimitExceeded</Code>", "Cannot exceed quota for AccessKeysPerUser: 2")
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"DeleteAccessKey"}, "UserName": {"carol"}, "AccessKeyId": {"not-a-key-id-00000"},
	}), http.StatusBadRequest, "<Code>ValidationError</Code>", "accessKeyId")
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"DeleteAccessKey"}, "UserName": {"carol"}, "AccessKeyId": {"AKIAAAAAAAAAAAAAAAAA"},
	}), http.StatusNotFound, "<Code>NoSuchEntity</Code>")
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"DeleteAccessKey"}, "UserName": {"carol"}, "AccessKeyId": {first},
	}), http.StatusOK)
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"DeleteAccessKey"}, "UserName": {"carol"}, "AccessKeyId": {first},
	}), http.StatusNotFound, "<Code>NoSuchEntity</Code>")
	// bob may act only on the users his policy names, so a missing user is
	// denied before it is looked up: nothing tells bob it does not exist.
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListAccessKeys"}, "UserName": {"ghost"}}),
		http.StatusForbidden, "<Code>AccessDenied</Code>")
}
