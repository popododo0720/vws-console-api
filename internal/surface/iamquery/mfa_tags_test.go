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

// seedMfaDevice adds the virtual MFA device the tag actions target and returns
// its serial number, the AWS SerialNumber.
func seedMfaDevice(t *testing.T, f *iam.Fake, root sigv4.Credential, name string) string {
	t.Helper()
	return f.AddMfaDevice(root.Account, name)
}

func TestMFADeviceTagActions(t *testing.T) {
	h, f, rec, root := harness(t)
	serial := seedMfaDevice(t, f, root, "alice-phone")
	form := url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {serial},
		"Tags.member.1.Key": {"Team"}, "Tags.member.1.Value": {"platform"},
		"Tags.member.2.Key": {"env"}, "Tags.member.2.Value": {"prod"},
	}
	res := call(t, h, root, sigv4.ServiceIAM, form)
	has(t, res, http.StatusOK, `<TagMFADeviceResponse>`, `<ResponseMetadata><RequestId>`)
	if body := res.Body.String(); strings.Contains(body, "<TagMFADeviceResult>") {
		t.Errorf("TagMFADevice has a result element: %s", body)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}}),
		http.StatusOK,
		`<ListMFADeviceTagsResult><IsTruncated>false</IsTruncated>`+
			`<Tags><member><Key>Team</Key><Value>platform</Value></member>`+
			`<member><Key>env</Key><Value>prod</Value></member></Tags></ListMFADeviceTagsResult>`)
	// A named key is overwritten and other keys stay.
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {serial},
		"Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"dev"},
	}), http.StatusOK)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}}),
		http.StatusOK, `<Key>env</Key><Value>dev</Value>`)
	// Untag ignores a key that is not attached.
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UntagMFADevice"}, "SerialNumber": {serial},
		"TagKeys.member.1": {"Team"}, "TagKeys.member.2": {"missing"},
	})
	has(t, res, http.StatusOK, `<UntagMFADeviceResponse>`, `<ResponseMetadata>`)
	if body := res.Body.String(); strings.Contains(body, "<UntagMFADeviceResult>") {
		t.Errorf("UntagMFADevice has a result element: %s", body)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}}),
		http.StatusOK, `<Tags><member><Key>env</Key><Value>dev</Value></member></Tags>`)
	for _, want := range []string{
		"iam:TagMFADevice " + serial,
		"iam:ListMFADeviceTags " + serial,
		"iam:UntagMFADevice " + serial,
	} {
		if !strings.Contains(strings.Join(rec.seen, "\n"), want) {
			t.Errorf("not authorized: %q in %v", want, rec.seen)
		}
	}
}

func TestMFADeviceTagPaging(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "paged-phone")
	form := url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	for i, key := range []string{"a", "b", "c"} {
		form.Set("Tags.member."+strconv.Itoa(i+1)+".Key", key)
		form.Set("Tags.member."+strconv.Itoa(i+1)+".Value", key+"-value")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusOK)
	list := url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}, "MaxItems": {"2"}}
	res := call(t, h, root, sigv4.ServiceIAM, list)
	has(t, res, http.StatusOK, `<IsTruncated>true</IsTruncated>`, `<Key>a</Key>`, `<Key>b</Key>`)
	m := regexp.MustCompile(`<Marker>([^<]+)</Marker>`).FindStringSubmatch(res.Body.String())
	if m == nil {
		t.Fatalf("no Marker in %s", res.Body.String())
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial},
		"MaxItems": {"2"}, "Marker": {m[1]},
	}), http.StatusOK, `<IsTruncated>false</IsTruncated>`,
		`<Tags><member><Key>c</Key><Value>c-value</Value></member></Tags>`)
}

func TestMFADeviceTagErrors(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "errors-phone")
	ghost := "arn:vws:iam::" + root.Account.String() + ":mfa/ghost"
	foreign := "arn:vws:iam::210987654321:mfa/errors-phone"
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"TagMFADevice"}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	for _, badSerial := range []string{"short", "arn vws:iam::123456789012:mfa/x"} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"TagMFADevice"}, "SerialNumber": {badSerial},
			"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	for _, action := range []string{"TagMFADevice", "UntagMFADevice"} {
		form := url.Values{"Action": {action}, "SerialNumber": {ghost}}
		if action == "TagMFADevice" {
			form.Set("Tags.member.1.Key", "k")
			form.Set("Tags.member.1.Value", "v")
		} else {
			form.Set("TagKeys.member.1", "k")
		}
		has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {foreign},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {ghost}}),
		http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"UntagMFADevice"}, "SerialNumber": {serial}}),
		http.StatusBadRequest, `<Code>ValidationError</Code>`)
	for _, tc := range []struct {
		name   string
		values map[string]string
		code   string
		member string
	}{
		{
			"invalid key character",
			map[string]string{"Tags.member.1.Key": "bad#key", "Tags.member.1.Value": "v"},
			"ValidationError", "tags.1.member.key",
		},
		{
			"invalid value character",
			map[string]string{"Tags.member.1.Key": "k", "Tags.member.1.Value": "bad#value"},
			"ValidationError", "tags.1.member.value",
		},
		{
			"key too long",
			map[string]string{
				"Tags.member.1.Key": strings.Repeat("k", iam.MaxTagKeyLen+1), "Tags.member.1.Value": "v",
			},
			"ValidationError", "tags.1.member.key",
		},
		{
			"value too long",
			map[string]string{
				"Tags.member.1.Key": "k", "Tags.member.1.Value": strings.Repeat("v", iam.MaxTagValueLen+1),
			},
			"ValidationError", "tags.1.member.value",
		},
		{
			"reserved key prefix",
			map[string]string{"Tags.member.1.Key": "aws:team", "Tags.member.1.Value": "v"},
			"InvalidInput", "",
		},
		{
			"reserved value prefix",
			map[string]string{"Tags.member.1.Key": "k", "Tags.member.1.Value": "aws:value"},
			"InvalidInput", "",
		},
		{
			"empty key",
			map[string]string{"Tags.member.1.Key": "", "Tags.member.1.Value": "v"},
			"ValidationError", "tags.1.member.key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
			for k, v := range tc.values {
				form.Set(k, v)
			}
			res := call(t, h, root, sigv4.ServiceIAM, form)
			has(t, res, http.StatusBadRequest, "<Code>"+tc.code+"</Code>")
			if tc.member != "" {
				has(t, res, http.StatusBadRequest, tc.member, "failed to satisfy constraint")
			}
		})
	}
	many := url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	for i := 1; i <= 51; i++ {
		many.Set("Tags.member."+strconv.Itoa(i)+".Key", "k"+strconv.Itoa(i))
		many.Set("Tags.member."+strconv.Itoa(i)+".Value", "v")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, many), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UntagMFADevice"}, "SerialNumber": {serial},
		"TagKeys.member.1": {"bad#key"},
	}), http.StatusBadRequest, `<Code>ValidationError</Code>`, "failed to satisfy constraint")
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"UntagMFADevice"}, "SerialNumber": {serial},
		"TagKeys.member.1": {strings.Repeat("k", iam.MaxTagKeyLen+1)},
	}), http.StatusBadRequest, `<Code>ValidationError</Code>`, "failed to satisfy constraint")
	for _, maxItems := range []string{"0", "1001", "many"} {
		form := url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}, "MaxItems": {maxItems}}
		has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	}
	// The 51st tag is LimitExceeded.
	fill := url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	for i := 1; i <= 50; i++ {
		fill.Set("Tags.member."+strconv.Itoa(i)+".Key", "k"+strconv.Itoa(i))
		fill.Set("Tags.member."+strconv.Itoa(i)+".Value", "v")
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, fill), http.StatusOK)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {serial},
		"Tags.member.1.Key": {"extra"}, "Tags.member.1.Value": {"v"},
	}), http.StatusConflict, `<Code>LimitExceeded</Code>`)
}

// Tagging a device also needs permission to list its tags, as in AWS.
func TestMFADeviceTagNeedsListPermission(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "bob-phone")
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "tag",
		`{"Statement":[{"Effect":"Allow","Action":["iam:TagMFADevice"],"Resource":"*"}]}`, ""); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	tag := url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {serial},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, tag), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	// Removing tags needs iam:UntagMFADevice only; the list permission is not required.
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "untag",
		`{"Statement":[{"Effect":"Allow","Action":["iam:UntagMFADevice"],"Resource":"*"}]}`, ""); err != nil {
		t.Fatal(err)
	}
	untag := url.Values{"Action": {"UntagMFADevice"}, "SerialNumber": {serial}, "TagKeys.member.1": {"k"}}
	has(t, call(t, h, bob, sigv4.ServiceIAM, untag), http.StatusOK, `<UntagMFADeviceResponse>`)
	tagAndList := `{"Statement":[{"Effect":"Allow","Action":["iam:TagMFADevice","iam:ListMFADeviceTags"],"Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "tag", tagAndList, ""); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, tag), http.StatusOK, `<TagMFADeviceResponse>`)
}

func TestMFADeviceTagRequiresTagMembers(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "member-phone")
	form := url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	form.Set("Tags.member.1.Key", "only-key")
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	form = url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	form.Set("Tags.member.1.Value", "only-value")
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusBadRequest, `<Code>ValidationError</Code>`)
	// An empty value that is present is the AWS empty tag value.
	form = url.Values{"Action": {"TagMFADevice"}, "SerialNumber": {serial}}
	form.Set("Tags.member.1.Key", "empty")
	form.Set("Tags.member.1.Value", "")
	has(t, call(t, h, root, sigv4.ServiceIAM, form), http.StatusOK, `<TagMFADeviceResponse>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}}),
		http.StatusOK, `<Tags><member><Key>empty</Key><Value></Value></member></Tags>`)
}

func TestListMFADeviceTagsParameterErrors(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "params-phone")
	base := url.Values{"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial}}
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

// A principal allowed on every serial must not reach a device by sending a
// serial with another partition, region or path. The exact serial stays
// covered by an explicit Deny.
func TestMFADeviceTagSerialVariantsStayInScope(t *testing.T) {
	h, f, _, root := harness(t)
	serial := seedMfaDevice(t, f, root, "scope-phone")
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	actions := `["iam:TagMFADevice","iam:UntagMFADevice","iam:ListMFADeviceTags"]`
	allow := `{"Statement":[{"Effect":"Allow","Action":` + actions + `,"Resource":"*"}]}`
	deny := `{"Statement":[{"Effect":"Deny","Action":` + actions + `,"Resource":"` + serial + `"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "allow", allow, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "deny", deny, ""); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	variants := []string{
		"arn:aws:iam::" + root.Account.String() + ":mfa/scope-phone",
		"arn:vws:iam:us-east-1:" + root.Account.String() + ":mfa/scope-phone",
		"arn:vws:iam::" + root.Account.String() + ":mfa/admin/scope-phone",
	}
	for _, wrong := range variants {
		has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
			"Action": {"TagMFADevice"}, "SerialNumber": {wrong},
			"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
		}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
		has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
			"Action": {"UntagMFADevice"}, "SerialNumber": {wrong}, "TagKeys.member.1": {"k"},
		}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
		has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
			"Action": {"ListMFADeviceTags"}, "SerialNumber": {wrong},
		}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	}
	// The exact serial is denied before the backend runs.
	for _, action := range []string{"TagMFADevice", "UntagMFADevice", "ListMFADeviceTags"} {
		form := url.Values{"Action": {action}, "SerialNumber": {serial}}
		switch action {
		case "TagMFADevice":
			form.Set("Tags.member.1.Key", "k")
			form.Set("Tags.member.1.Value", "v")
		case "UntagMFADevice":
			form.Set("TagKeys.member.1", "k")
		}
		has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADeviceTags"}, "SerialNumber": {serial},
	}), http.StatusOK, `<Tags></Tags>`)
}
