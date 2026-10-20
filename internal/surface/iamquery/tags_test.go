package iamquery

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const policyTagARN = "arn:vws:iam::123456789012:policy/tagged"

func createTagPolicy(t *testing.T, h http.Handler, root sigv4.Credential) {
	t.Helper()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	form := url.Values{"Action": {"CreatePolicy"}, "PolicyName": {"tagged"}, "PolicyDocument": {doc}}
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusOK)
}

func TestPolicyTagActions(t *testing.T) {
	h, _, rec, root := harness(t)
	createTagPolicy(t, h, root)
	form := url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN},
		"Tags.member.1.Key": {"Team"}, "Tags.member.1.Value": {"platform"},
		"Tags.member.2.Key": {"env"}, "Tags.member.2.Value": {"prod"},
	}
	res := call(t, h, root, sigv4.ServiceIAM, form)
	has(t, res, http.StatusOK, `<TagPolicyResponse>`, `<ResponseMetadata><RequestId>`)
	if body := res.Body.String(); strings.Contains(body, "<TagPolicyResult>") {
		t.Errorf("TagPolicy has a result element: %s", body)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}}),
		http.StatusOK,
		`<ListPolicyTagsResult><IsTruncated>false</IsTruncated>`+
			`<Tags><member><Key>Team</Key><Value>platform</Value></member>`+
			`<member><Key>env</Key><Value>prod</Value></member></Tags></ListPolicyTagsResult>`)
	// A named key is overwritten and other keys stay.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN},
		"Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"dev"},
	}), http.StatusOK)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}}),
		http.StatusOK, `<Key>env</Key><Value>dev</Value>`)
	// Untag ignores a key that is not attached.
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UntagPolicy"}, "PolicyArn": {policyTagARN},
		"TagKeys.member.1": {"Team"}, "TagKeys.member.2": {"missing"},
	})
	has(t, res, http.StatusOK, `<UntagPolicyResponse>`, `<ResponseMetadata>`)
	if body := res.Body.String(); strings.Contains(body, "<UntagPolicyResult>") {
		t.Errorf("UntagPolicy has a result element: %s", body)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}}),
		http.StatusOK, `<Tags><member><Key>env</Key><Value>dev</Value></member></Tags>`)
	for _, want := range []string{
		"iam:TagPolicy " + policyTagARN,
		"iam:ListPolicyTags " + policyTagARN,
		"iam:UntagPolicy " + policyTagARN,
	} {
		if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
			t.Errorf("not authorized: %q in %v", want, rec.seen)
		}
	}
}

func TestPolicyTagPaging(t *testing.T) {
	h, _, _, root := harness(t)
	createTagPolicy(t, h, root)
	form := url.Values{"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN}}
	for i, key := range []string{"a", "b", "c"} {
		form.Set("Tags.member."+string(rune('1'+i))+".Key", key)
		form.Set("Tags.member."+string(rune('1'+i))+".Value", key+"-value")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusOK)
	list := url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}, "MaxItems": {"2"}}
	res := call(t, h, root, sigv4.ServiceIAM, list)
	has(t, res, http.StatusOK, `<IsTruncated>true</IsTruncated>`, `<Key>a</Key>`, `<Key>b</Key>`)
	m := regexp.MustCompile(`<Marker>([^<]+)</Marker>`).FindStringSubmatch(res.Body.String())
	if m == nil {
		t.Fatalf("no Marker in %s", res.Body.String())
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN},
		"MaxItems": {"2"}, "Marker": {m[1]},
	}),
		http.StatusOK, `<IsTruncated>false</IsTruncated>`, `<Tags><member><Key>c</Key><Value>c-value</Value></member></Tags>`)
}

func TestPolicyTagErrors(t *testing.T) {
	h, _, _, root := harness(t)
	createTagPolicy(t, h, root)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"TagPolicy"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {"arn:short"},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	ghost := "arn:vws:iam::123456789012:policy/ghost"
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {ghost},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	}),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {ghost}}),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	for _, tc := range []struct {
		name   string
		values map[string]string
	}{
		{"invalid key character", map[string]string{"Tags.member.1.Key": "bad#key", "Tags.member.1.Value": "v"}},
		{"invalid value character", map[string]string{"Tags.member.1.Key": "k", "Tags.member.1.Value": "bad#value"}},
		{"reserved key prefix", map[string]string{"Tags.member.1.Key": "aws:team", "Tags.member.1.Value": "v"}},
		{"reserved value prefix", map[string]string{"Tags.member.1.Key": "k", "Tags.member.1.Value": "aws:value"}},
		{"empty key", map[string]string{"Tags.member.1.Key": "", "Tags.member.1.Value": "v"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN}}
			for k, v := range tc.values {
				form.Set(k, v)
			}
			has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
		})
	}
	many := url.Values{"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN}}
	for i := 1; i <= 51; i++ {
		many.Set("Tags.member."+strconv.Itoa(i)+".Key", "k"+strconv.Itoa(i))
		many.Set("Tags.member."+strconv.Itoa(i)+".Value", "v")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, many), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"UntagPolicy"}, "PolicyArn": {policyTagARN}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UntagPolicy"}, "PolicyArn": {policyTagARN},
		"TagKeys.member.1": {"bad#key"},
	}), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	for _, maxItems := range []string{"0", "1001", "many"} {
		form := url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}, "MaxItems": {maxItems}}
		has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	// The 51st tag is LimitExceeded.
	fill := url.Values{"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN}}
	for i := 1; i <= 50; i++ {
		fill.Set("Tags.member."+strconv.Itoa(i)+".Key", "k"+strconv.Itoa(i))
		fill.Set("Tags.member."+strconv.Itoa(i)+".Value", "v")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, fill), http.StatusOK)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN},
		"Tags.member.1.Key": {"extra"}, "Tags.member.1.Value": {"v"},
	}), http.StatusConflict, `<Code>LimitExceeded</Code>`)
}

// Tagging and untagging also need permission to list tags, as in AWS.
func TestPolicyTagNeedsListPermission(t *testing.T) {
	h, f, _, root := harness(t)
	createTagPolicy(t, h, root)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "tag",
		`{"Statement":[{"Effect":"Allow","Action":["iam:TagPolicy"],"Resource":"*"}]}`); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	tag := url.Values{
		"Action": {"TagPolicy"}, "PolicyArn": {policyTagARN},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, tag), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "tag",
		`{"Statement":[{"Effect":"Allow","Action":["iam:TagPolicy","iam:ListPolicyTags"],"Resource":"*"}]}`); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, tag), http.StatusOK, `<TagPolicyResponse>`)
}

func TestListPolicyTagsParameterErrors(t *testing.T) {
	h, _, _, root := harness(t)
	createTagPolicy(t, h, root)
	base := url.Values{"Action": {"ListPolicyTags"}, "PolicyArn": {policyTagARN}}
	bad := url.Values{}
	for k, v := range base {
		bad[k] = v
	}
	bad.Set("Marker", "bad\x01marker")
	has(t, call(t, h, root, sigv4.ServiceIAM, bad), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
	unsupported := url.Values{}
	for k, v := range base {
		unsupported[k] = v
	}
	unsupported.Set("PathPrefix", "/")
	has(t, call(t, h, root, sigv4.ServiceIAM, unsupported), http.StatusBadRequest, `<Code>InvalidInput</Code>`)
}
