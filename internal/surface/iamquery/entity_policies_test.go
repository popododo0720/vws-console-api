package iamquery

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const s3Doc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

func seedManaged(t *testing.T, f *iam.Fake, account resource.AccountID, name, path string) string {
	t.Helper()
	p, err := f.CreatePolicy(t.Context(), account, name, path, s3Doc, "")
	if err != nil {
		t.Fatal(err)
	}
	return p.ARN
}

func attachedTo(t *testing.T, f *iam.Fake, account resource.AccountID, kind iam.Entity, name string) []string {
	t.Helper()
	ps, err := f.ListAttachedPolicies(
		t.Context(), account, kind, name, backendtest.EntityGrant(t.Context(), t, f, account, kind, name),
	)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func inlineOf(t *testing.T, f *iam.Fake, account resource.AccountID, kind iam.Entity, name string) []string {
	t.Helper()
	ns, err := f.ListInlinePolicies(
		t.Context(), account, kind, name, backendtest.EntityGrant(t.Context(), t, f, account, kind, name),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

// #314 bundle 3: a user or group policy call acts only on the entity the
// caller was authorized on. When the user or group moves to a denied path
// between the authorization and the call, the answer is 409
// ConcurrentModification: nothing is attached, detached, put or deleted, and
// nothing is listed or read. Without the move the same requests succeed, so
// the policy allows them.
func TestEntityPolicyCallsActOnTheAuthorizedARN(t *testing.T) {
	for _, e := range []struct {
		word, key, name string
		kind            iam.Entity
	}{
		{"User", "UserName", "carol", iam.EntityUser},
		{"Group", "GroupName", "devs", iam.EntityGroup},
	} {
		for _, tc := range []struct {
			action string
			form   url.Values
			// read: the body must not carry what the entity holds.
			read bool
		}{
			{"Attach" + e.word + "Policy", url.Values{"PolicyArn": {"Other"}}, false},
			{"Detach" + e.word + "Policy", url.Values{"PolicyArn": {"Kept"}}, false},
			{"ListAttached" + e.word + "Policies", url.Values{}, true},
			{"Put" + e.word + "Policy", url.Values{"PolicyName": {"new"}, "PolicyDocument": {s3Doc}}, false},
			{"Get" + e.word + "Policy", url.Values{"PolicyName": {"keep"}}, true},
			{"Delete" + e.word + "Policy", url.Values{"PolicyName": {"keep"}}, false},
			{"List" + e.word + "Policies", url.Values{}, true},
		} {
			for _, moved := range []bool{false, true} {
				name := tc.action + "/not moved"
				var mover *movingAdmin
				if moved {
					name = tc.action + "/moved after authorization"
					mover = &movingAdmin{tb: t}
					if e.kind == iam.EntityUser {
						mover.user = e.name
					} else {
						mover.group = e.name
					}
				}
				t.Run(name, func(t *testing.T) {
					h, f, account, bob := authorizedPrincipalHarness(t, mover)
					arns := map[string]string{
						"Kept": seedManaged(t, f, account, "Kept", "/"), "Other": seedManaged(t, f, account, "Other", "/"),
					}
					ctx := t.Context()
					if err := f.AttachPolicy(
						ctx, account, e.kind, e.name, arns["Kept"], backendtest.EntityGrant(ctx, t, f, account, e.kind, e.name),
					); err != nil {
						t.Fatal(err)
					}
					if err := f.PutInlinePolicy(
						ctx, account, e.kind, e.name, "keep", s3Doc, backendtest.EntityGrant(ctx, t, f, account, e.kind, e.name),
					); err != nil {
						t.Fatal(err)
					}
					form := url.Values{"Action": {tc.action}, e.key: {e.name}}
					for k, v := range tc.form {
						form[k] = v
						if k == "PolicyArn" {
							form[k] = []string{arns[v[0]]}
						}
					}
					res := call(t, h, bob, sigv4.ServiceIAM, form)
					if !moved {
						has(t, res, http.StatusOK)
						return
					}
					has(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
					if got := attachedTo(t, f, account, e.kind, e.name); !slices.Equal(got, []string{"Kept"}) {
						t.Errorf("attached %q, want only Kept", got)
					}
					if got := inlineOf(t, f, account, e.kind, e.name); !slices.Equal(got, []string{"keep"}) {
						t.Errorf("inline %q, want only keep", got)
					}
					if tc.read && (strings.Contains(res.Body.String(), "Kept") || strings.Contains(res.Body.String(), "keep") ||
						strings.Contains(res.Body.String(), "PolicyDocument")) {
						t.Errorf("a policy was returned: %s", res.Body)
					}
				})
			}
		}
	}
}

// #314 bundle 3: ListAttached*Policies pages by name with Marker and
// MaxItems and filters on the policy path; List*Policies pages and takes no
// PathPrefix.
func TestEntityPolicyListsPage(t *testing.T) {
	h, f, account, bob := authorizedPrincipalHarness(t, nil)
	ctx := t.Context()
	for _, p := range [][2]string{{"A", "/"}, {"B", "/x/"}, {"C", "/x/y/"}} {
		arn := seedManaged(t, f, account, p[0], p[1])
		for _, kind := range []iam.Entity{iam.EntityUser, iam.EntityGroup} {
			name := map[iam.Entity]string{iam.EntityUser: "carol", iam.EntityGroup: "devs"}[kind]
			if err := f.AttachPolicy(
				ctx, account, kind, name, arn, backendtest.EntityGrant(ctx, t, f, account, kind, name),
			); err != nil {
				t.Fatal(err)
			}
			if err := f.PutInlinePolicy(
				ctx, account, kind, name, strings.ToLower(p[0]), s3Doc, backendtest.EntityGrant(ctx, t, f, account, kind, name),
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	marker := regexp.MustCompile(`<Marker>([^<]+)</Marker>`)
	for _, e := range []struct{ word, key, name string }{{"User", "UserName", "carol"}, {"Group", "GroupName", "devs"}} {
		list := func(action string, kv ...string) url.Values {
			v := url.Values{"Action": {action}, e.key: {e.name}}
			for i := 0; i < len(kv); i += 2 {
				v.Set(kv[i], kv[i+1])
			}
			return v
		}
		attached := "ListAttached" + e.word + "Policies"
		res := call(t, h, bob, sigv4.ServiceIAM, list(attached, "MaxItems", "2"))
		has(t, res, http.StatusOK, "<"+attached+"Result>", "<AttachedPolicies><member><PolicyName>A</PolicyName>",
			"<PolicyArn>arn:vws:iam::"+account.String()+":policy/x/B</PolicyArn>", "<IsTruncated>true</IsTruncated>",
			"<Marker>B</Marker>")
		m := marker.FindStringSubmatch(res.Body.String())
		if m == nil {
			t.Fatalf("no Marker: %s", res.Body)
		}
		res = call(t, h, bob, sigv4.ServiceIAM, list(attached, "MaxItems", "2", "Marker", m[1]))
		has(t, res, http.StatusOK, "<PolicyName>C</PolicyName>", "<IsTruncated>false</IsTruncated>")
		if body := res.Body.String(); strings.Contains(body, "<PolicyName>B</PolicyName>") ||
			strings.Contains(body, "<Marker>") {
			t.Errorf("page 2: %s", res.Body)
		}
		res = call(t, h, bob, sigv4.ServiceIAM, list(attached, "PathPrefix", "/x/"))
		has(t, res, http.StatusOK, "<PolicyName>B</PolicyName>", "<PolicyName>C</PolicyName>")
		if strings.Contains(res.Body.String(), "<PolicyName>A</PolicyName>") {
			t.Errorf("PathPrefix /x/ lists A: %s", res.Body)
		}
		for _, bad := range [][]string{
			{"PathPrefix", "x"},
			{"PathPrefix", "/x"},
			{"PathPrefix", "/a b/"},
			{"MaxItems", "0"},
			{"MaxItems", "1001"},
		} {
			has(t, call(t, h, bob, sigv4.ServiceIAM, list(attached, bad...)), http.StatusBadRequest,
				"<Code>ValidationError</Code>")
		}
		has(t, call(t, h, bob, sigv4.ServiceIAM, list(attached, "Marker", "")), http.StatusBadRequest,
			"The Marker value is invalid.")

		inline := "List" + e.word + "Policies"
		res = call(t, h, bob, sigv4.ServiceIAM, list(inline, "MaxItems", "2"))
		has(t, res, http.StatusOK, "<"+inline+"Result>", "<PolicyNames><member>a</member><member>b</member></PolicyNames>",
			"<IsTruncated>true</IsTruncated>", "<Marker>b</Marker>")
		res = call(t, h, bob, sigv4.ServiceIAM, list(inline, "Marker", "b"))
		has(t, res, http.StatusOK, "<PolicyNames><member>c</member></PolicyNames>", "<IsTruncated>false</IsTruncated>")
		has(t, call(t, h, bob, sigv4.ServiceIAM, list(inline, "PathPrefix", "/")), http.StatusBadRequest,
			"<Code>InvalidInput</Code>")
		has(t, call(t, h, bob, sigv4.ServiceIAM, list(inline, "MaxItems", "0")), http.StatusBadRequest,
			"<Code>ValidationError</Code>")
	}
}

// #314 bundle 3: the user and group policy actions answer the AWS codes and
// messages for bad input, quotas and missing policies, and return inline
// documents URL-encoded.
func TestEntityPolicyErrorsAndShapes(t *testing.T) {
	h, f, account, bob := authorizedPrincipalHarness(t, nil)
	arn := "arn:vws:iam::" + account.String() + ":"
	var managed []string
	for i := range 11 {
		managed = append(managed, seedManaged(t, f, account, "M"+string(rune('a'+i)), "/"))
	}
	form := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for i, p := range managed {
		res := call(t, h, bob, sigv4.ServiceIAM, form("Action", "AttachUserPolicy", "UserName", "carol", "PolicyArn", p))
		if i < 10 {
			has(t, res, http.StatusOK, "<AttachUserPolicyResponse")
			continue
		}
		has(t, res, http.StatusConflict, "<Code>LimitExceeded</Code>", "Cannot exceed quota for PoliciesPerUser: 10")
	}
	for _, tc := range []struct {
		form   url.Values
		status int
		parts  []string
	}{
		{
			form("Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", "arn:short"), 400,
			[]string{"<Code>ValidationError</Code>", "policyArn"},
		},
		{
			form("Action", "AttachGroupPolicy", "GroupName", "devs", "PolicyArn", arn+"user/ok/carol"), 400,
			[]string{"<Code>InvalidInput</Code>", "ARN " + arn + "user/ok/carol is not valid."},
		},
		{
			form("Action", "DetachGroupPolicy", "GroupName", "devs", "PolicyArn", arn+"policy/Ghost"), 404,
			[]string{"<Code>NoSuchEntity</Code>", "Policy " + arn + "policy/Ghost does not exist or is not attachable."},
		},
		{
			form("Action", "DetachGroupPolicy", "GroupName", "devs", "PolicyArn", managed[0]), 404,
			[]string{"<Code>NoSuchEntity</Code>", "Policy " + managed[0] + " was not found."},
		},
		{
			form("Action", "AttachGroupPolicy", "GroupName", "devs"), 400,
			[]string{"<Code>ValidationError</Code>", "policyArn"},
		},
		{
			form("Action", "PutGroupPolicy", "GroupName", "devs", "PolicyName", "bad name", "PolicyDocument", s3Doc), 400,
			[]string{"<Code>ValidationError</Code>", "policyName"},
		},
		{
			form("Action", "PutGroupPolicy", "GroupName", "devs",
				"PolicyName", strings.Repeat("p", 129), "PolicyDocument", s3Doc),
			400,
			[]string{"<Code>ValidationError</Code>", "policyName"},
		},
		{
			form("Action", "PutGroupPolicy", "GroupName", "devs", "PolicyName", "p", "PolicyDocument", "{\u0100}"), 400,
			[]string{"<Code>ValidationError</Code>", "policyDocument"},
		},
		{form("Action", "PutGroupPolicy", "GroupName", "devs", "PolicyName", "p",
			"PolicyDocument", strings.Repeat(" ", 131073)), 400, []string{"<Code>ValidationError</Code>", "policyDocument"}},
		{
			form("Action", "PutGroupPolicy", "GroupName", "devs", "PolicyName", "p", "PolicyDocument", `{"Statement":[]}`), 400,
			[]string{"<Code>MalformedPolicyDocument</Code>"},
		},
		{
			form("Action", "PutGroupPolicy", "GroupName", "devs", "PolicyName", "p"), 400,
			[]string{"<Code>ValidationError</Code>", "policyDocument"},
		},
		{
			form("Action", "PutUserPolicy", "UserName", "carol", "PolicyName", "big",
				"PolicyDocument", strings.Replace(s3Doc, `"*"`, `"arn:vws:s3:::`+strings.Repeat("x", 2048)+`"`, 1)), 409,
			[]string{"<Code>LimitExceeded</Code>", "Maximum policy size of 2048 bytes exceeded for user carol."},
		},
		{
			form("Action", "PutUserPolicy", "UserName", "carol", "PolicyName", "s3", "PolicyDocument", s3Doc+"\n"), 200,
			[]string{"<PutUserPolicyResponse"},
		},
		{form("Action", "GetUserPolicy", "UserName", "carol", "PolicyName", "s3"), 200, []string{
			"<GetUserPolicyResult><UserName>carol</UserName><PolicyName>s3</PolicyName>",
			"<PolicyDocument>%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22" +
				"%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D%0A</PolicyDocument>",
		}},
		{
			form("Action", "GetUserPolicy", "UserName", "carol", "PolicyName", "zzz"), 404,
			[]string{"<Code>NoSuchEntity</Code>", "The user policy with name zzz cannot be found."},
		},
		{
			form("Action", "DeleteGroupPolicy", "GroupName", "devs", "PolicyName", "zzz"), 404,
			[]string{"<Code>NoSuchEntity</Code>", "The group policy with name zzz cannot be found."},
		},
		{form("Action", "GetUserPolicy", "UserName", "carol"), 400, []string{"<Code>ValidationError</Code>", "policyName"}},
		// Without UserName or GroupName the call is authorized on the caller,
		// as the other user and group actions are, and bob may not act on
		// himself.
		{form("Action", "DeleteUserPolicy", "PolicyName", "s3"), 403, []string{"<Code>AccessDenied</Code>"}},
		{form("Action", "ListUserPolicies"), 403, []string{"<Code>AccessDenied</Code>"}},
		{form("Action", "ListAttachedGroupPolicies"), 403, []string{"<Code>AccessDenied</Code>"}},
		{
			form("Action", "DeleteUserPolicy", "UserName", "carol", "PolicyName", "s3"), 200,
			[]string{"<DeleteUserPolicyResponse"},
		},
	} {
		res := call(t, h, bob, sigv4.ServiceIAM, tc.form)
		if res.Code != tc.status {
			t.Errorf("%v: status %d, want %d: %s", tc.form, res.Code, tc.status, res.Body)
			continue
		}
		for _, p := range tc.parts {
			if !strings.Contains(res.Body.String(), p) {
				t.Errorf("%v: missing %q in %s", tc.form, p, res.Body)
			}
		}
	}
	if got := attachedTo(t, f, account, iam.EntityGroup, "devs"); len(got) != 0 {
		t.Errorf("devs has %q attached", got)
	}
	if got := inlineOf(t, f, account, iam.EntityGroup, "devs"); len(got) != 0 {
		t.Errorf("devs has inline %q", got)
	}
}
