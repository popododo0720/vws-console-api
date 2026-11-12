package console

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAdminConnectionRequiresRootKeyAndCSRF(t *testing.T) {
	for _, path := range []string{
		regionPath + "/test", regionPath + "/pve-lab-1/test",
		accountPath + "/test", accountPath + "/" + accountID + "/test",
	} {
		t.Run(path, func(t *testing.T) {
			e, _, _, _ := accountFixture(t)
			calls := 0
			h := e.h.(*handler)
			h.accountConnection = func(context.Context, resource.AWSConnectionRequest, string) []resource.ConnectionStep {
				calls++
				return resource.AWSConnectionSteps(true, true)
			}
			user, _ := e.login(t)
			rec := e.do(t, "POST", path, "{}", map[string]string{CSRFHeader: csrfToken(user.Value)}, user)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("non-root: %d %s", rec.Code, rec.Body)
			}
			e.h.(*handler).adminKey = nil
			rec = e.do(t, "POST", path, "{}", map[string]string{"Authorization": "Bearer tok"})
			if rec.Code != http.StatusServiceUnavailable || calls != 0 {
				t.Fatalf("missing key: %d %s", rec.Code, rec.Body)
			}
			if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
				t.Fatal(err)
			}
			login := e.do(t, "POST", "/api/v1/auth/login",
				`{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
			root := cookie(t, login, SessionCookie)
			rec = e.do(t, "POST", path, "{}", nil, root)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("missing CSRF: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestAdminConnectionRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		path, body, field string
	}{
		{regionPath + "/test", `null`, "body"},
		{regionPath + "/test", `{"tokenSecret":"canary","unknown":true}`, "body"},
		{regionPath + "/test", `{}`, "name"},
		{regionPath + "/bad/test", `{}`, "name"},
		{regionPath + "/pve-lab-1/test", `{"name":"pve-other-1"}`, "name"},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			e, _, _, _ := accountFixture(t)
			rec := e.do(t, "POST", tc.path, tc.body, map[string]string{"Authorization": "Bearer tok"})
			if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"field":"`+tc.field+`"`) {
				t.Fatalf("invalid input: %d %s", rec.Code, rec.Body)
			}
		})
	}
}
