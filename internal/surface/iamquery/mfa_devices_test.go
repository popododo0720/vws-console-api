package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type virtualMFADevicesXML struct {
	Result struct {
		Devices []struct {
			SerialNumber string   `xml:"SerialNumber"`
			User         *userXML `xml:"User"`
			EnableDate   string   `xml:"EnableDate"`
		} `xml:"VirtualMFADevices>member"`
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
	} `xml:"ListVirtualMFADevicesResult"`
}

func TestListVirtualMFADevices(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "alice", "/eng/"); err != nil {
		t.Fatal(err)
	}
	assigned := f.AddMfaDevice(root.Account, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, assigned, "alice", now); err != nil {
		t.Fatal(err)
	}
	spare := f.AddMfaDevice(root.Account, "spare-phone")

	res := call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}})
	has(t, res, http.StatusOK, `<ListVirtualMFADevicesResponse>`, `<ListVirtualMFADevicesResult>`,
		`<ResponseMetadata><RequestId>`)
	var body virtualMFADevicesXML
	if err := xml.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v\n%s", err, res.Body.String())
	}
	if body.Result.IsTruncated || body.Result.Marker != "" || len(body.Result.Devices) != 2 {
		t.Fatalf("result %+v", body.Result)
	}
	first, second := body.Result.Devices[0], body.Result.Devices[1]
	if first.SerialNumber != assigned || second.SerialNumber != spare {
		t.Fatalf("serials %q %q, want %q %q", first.SerialNumber, second.SerialNumber, assigned, spare)
	}
	if first.User == nil || first.User.UserName != "alice" || first.User.Path != "/eng/" ||
		first.User.Arn != "arn:vws:iam::123456789012:user/eng/alice" || first.User.UserID == "" {
		t.Errorf("assigned user %+v", first.User)
	}
	if first.EnableDate != "2026-10-09T10:00:00Z" {
		t.Errorf("enable date %q", first.EnableDate)
	}
	if second.User != nil || second.EnableDate != "" {
		t.Errorf("unassigned device %+v", second)
	}
	if want := "iam:ListVirtualMFADevices *"; len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}

	for _, tc := range []struct {
		assignment string
		want       string
	}{
		{"Assigned", assigned},
		{"Unassigned", spare},
	} {
		res := call(t, h, root, sigv4.ServiceIAM, url.Values{
			"Action": {"ListVirtualMFADevices"}, "AssignmentStatus": {tc.assignment},
		})
		has(t, res, http.StatusOK)
		var page virtualMFADevicesXML
		if err := xml.Unmarshal(res.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Result.Devices) != 1 || page.Result.Devices[0].SerialNumber != tc.want {
			t.Errorf("%s gave %+v", tc.assignment, page.Result.Devices)
		}
	}
}

func TestListVirtualMFADevicesPaging(t *testing.T) {
	h, f, _, root := harness(t)
	for _, name := range []string{"b-phone", "a-phone", "c-phone"} {
		f.AddMfaDevice(root.Account, name)
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListVirtualMFADevices"}, "MaxItems": {"2"},
	})
	has(t, res, http.StatusOK, `<IsTruncated>true</IsTruncated>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/a-phone</SerialNumber>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/b-phone</SerialNumber>`)
	var first virtualMFADevicesXML
	if err := xml.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Result.Marker != "arn:vws:iam::123456789012:mfa/b-phone" {
		t.Fatalf("marker %q", first.Result.Marker)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListVirtualMFADevices"}, "MaxItems": {"2"}, "Marker": {first.Result.Marker},
	})
	has(t, res, http.StatusOK, `<IsTruncated>false</IsTruncated>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/c-phone</SerialNumber>`)
}

func TestListVirtualMFADevicesParameterErrors(t *testing.T) {
	h, _, _, root := harness(t)
	for _, tc := range []struct {
		name   string
		values url.Values
		status int
		code   string
	}{
		{"bad assignment status", url.Values{"AssignmentStatus": {"assigned"}}, http.StatusBadRequest, "ValidationError"},
		{"zero max items", url.Values{"MaxItems": {"0"}}, http.StatusBadRequest, "ValidationError"},
		{"large max items", url.Values{"MaxItems": {"1001"}}, http.StatusBadRequest, "ValidationError"},
		{"path prefix", url.Values{"PathPrefix": {"/"}}, http.StatusBadRequest, "InvalidInput"},
		{"bad marker", url.Values{"Marker": {"\x01"}}, http.StatusBadRequest, "InvalidInput"},
		{"empty marker", url.Values{"Marker": {""}}, http.StatusBadRequest, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.values.Set("Action", "ListVirtualMFADevices")
			has(t, call(t, h, root, sigv4.ServiceIAM, tc.values), tc.status, `<Code>`+tc.code+`</Code>`)
		})
	}
}

func TestListVirtualMFADevicesAuthorizes(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	f.AddMfaDevice(root.Account, "alice-phone")
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	allowTags := `{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADeviceTags","Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allowTags); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusForbidden, `<Code>AccessDenied</Code>`)
	allowList := `{"Statement":[{"Effect":"Allow","Action":"iam:ListVirtualMFADevices","Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allowList); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListVirtualMFADevices"}}),
		http.StatusOK, `<ListVirtualMFADevicesResponse>`)
}

type mfaDevicesXML struct {
	Result struct {
		Devices []struct {
			UserName     string `xml:"UserName"`
			SerialNumber string `xml:"SerialNumber"`
			EnableDate   string `xml:"EnableDate"`
		} `xml:"MFADevices>member"`
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
	} `xml:"ListMFADevicesResult"`
}

func TestListMFADevices(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	for _, name := range []string{"alice", "bob", "carol"} {
		if _, err := f.CreateUser(ctx, root.Account, name, "/"); err != nil {
			t.Fatal(err)
		}
	}
	alicePhone := f.AddMfaDevice(root.Account, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, alicePhone, "alice", now); err != nil {
		t.Fatal(err)
	}
	bobPhone := f.AddMfaDevice(root.Account, "bob-phone")
	if err := f.AssignMfaDevice(root.Account, bobPhone, "bob", now); err != nil {
		t.Fatal(err)
	}

	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"alice"},
	})
	has(t, res, http.StatusOK,
		`<ListMFADevicesResponse><ListMFADevicesResult><MFADevices><member>`+
			`<UserName>alice</UserName>`+
			`<SerialNumber>arn:vws:iam::123456789012:mfa/alice-phone</SerialNumber>`+
			`<EnableDate>2026-10-09T10:00:00Z</EnableDate></member></MFADevices>`+
			`<IsTruncated>false</IsTruncated></ListMFADevicesResult>`+
			`<ResponseMetadata><RequestId>`)
	if strings.Contains(res.Body.String(), bobPhone) {
		t.Errorf("listed another user's device: %s", res.Body.String())
	}
	var body mfaDevicesXML
	if err := xml.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v\n%s", err, res.Body.String())
	}
	if len(body.Result.Devices) != 1 || body.Result.Devices[0].UserName != "alice" ||
		body.Result.Devices[0].SerialNumber != alicePhone ||
		body.Result.Devices[0].EnableDate != "2026-10-09T10:00:00Z" {
		t.Fatalf("result %+v", body.Result)
	}
	if body.Result.IsTruncated || body.Result.Marker != "" {
		t.Errorf("paging fields %+v", body.Result)
	}
	if want := "iam:ListMFADevices arn:vws:iam::123456789012:user/alice"; len(rec.seen) == 0 ||
		rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}

	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"nobody"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"carol"},
	}), http.StatusOK, `<ListMFADevicesResult><MFADevices></MFADevices>`+
		`<IsTruncated>false</IsTruncated></ListMFADevicesResult>`)
}

func TestListMFADevicesPaging(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	const first = "arn:vws:iam::123456789012:mfa/a-phone"
	for _, name := range []string{"b-phone", "a-phone", "c-phone"} {
		serial := f.AddMfaDevice(root.Account, name)
		if err := f.AssignMfaDevice(root.Account, serial, "alice", now); err != nil {
			t.Fatal(err)
		}
	}
	res := call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"alice"}, "MaxItems": {"2"},
	})
	has(t, res, http.StatusOK, `<IsTruncated>true</IsTruncated>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/a-phone</SerialNumber>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/b-phone</SerialNumber>`)
	var page mfaDevicesXML
	if err := xml.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Result.Marker != "arn:vws:iam::123456789012:mfa/b-phone" {
		t.Fatalf("marker %q", page.Result.Marker)
	}
	if len(page.Result.Devices) != 2 || page.Result.Devices[0].SerialNumber != first {
		t.Fatalf("first page %+v", page.Result)
	}
	res = call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"alice"},
		"MaxItems": {"2"}, "Marker": {page.Result.Marker},
	})
	has(t, res, http.StatusOK, `<IsTruncated>false</IsTruncated>`,
		`<SerialNumber>arn:vws:iam::123456789012:mfa/c-phone</SerialNumber>`)
}

func TestListMFADevicesParameterErrors(t *testing.T) {
	h, _, _, root := harness(t)
	longName := strings.Repeat("a", 129)
	largeMax := url.Values{"UserName": {"alice"}, "MaxItems": {"1001"}}
	for _, tc := range []struct {
		name   string
		values url.Values
		status int
		code   string
	}{
		{"empty marker", url.Values{"UserName": {"alice"}, "Marker": {""}}, http.StatusBadRequest, "InvalidInput"},
		{"zero max items", url.Values{"UserName": {"alice"}, "MaxItems": {"0"}}, http.StatusBadRequest, "ValidationError"},
		{"large max items", largeMax, http.StatusBadRequest, "ValidationError"},
		{"path prefix", url.Values{"PathPrefix": {"/"}}, http.StatusBadRequest, "InvalidInput"},
		{"bad user name", url.Values{"UserName": {"bad#name"}}, http.StatusBadRequest, "ValidationError"},
		{"long user name", url.Values{"UserName": {longName}}, http.StatusBadRequest, "ValidationError"},
		{"empty user name", url.Values{"UserName": {""}}, http.StatusBadRequest, "ValidationError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.values.Set("Action", "ListMFADevices")
			has(t, call(t, h, root, sigv4.ServiceIAM, tc.values), tc.status, `<Code>`+tc.code+`</Code>`)
		})
	}
}

func TestListMFADevicesAuthorizes(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	serial := f.AddMfaDevice(root.Account, "bob-phone")
	if err := f.AssignMfaDevice(root.Account, serial, "bob", now); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}

	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}}),
		http.StatusForbidden, `<Code>AccessDenied</Code>`)
	allow := `{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allow); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}}),
		http.StatusOK, `<ListMFADevicesResponse>`, `<UserName>bob</UserName>`)
	if want := "iam:ListMFADevices arn:vws:iam::123456789012:user/bob"; len(rec.seen) == 0 ||
		rec.seen[len(rec.seen)-1] != want {
		t.Errorf("authorized %v, want last %q", rec.seen, want)
	}
}

func TestListMFADevicesDefaultsToCaller(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	serial := f.AddMfaDevice(root.Account, "bob-phone")
	if err := f.AssignMfaDevice(root.Account, serial, "bob", now); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	allow := `{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "default", allow); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{"Action": {"ListMFADevices"}}),
		http.StatusOK, `<UserName>bob</UserName>`, `<SerialNumber>`+serial+`</SerialNumber>`)
}

// AWS authorizes ListMFADevices on the user whose devices are listed (the
// named user, else the caller), so a policy scoped to user/${aws:username}
// lets a user list only their own devices.
func TestListMFADevicesIsScopedToTheUser(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	alice, err := f.CreateUser(ctx, root.Account, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	bobUser, err := f.CreateUser(ctx, root.Account, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	alicePhone := f.AddMfaDevice(root.Account, "alice-phone")
	if err := f.AssignMfaDevice(root.Account, alicePhone, "alice", now); err != nil {
		t.Fatal(err)
	}
	bobPhone := f.AddMfaDevice(root.Account, "bob-phone")
	if err := f.AssignMfaDevice(root.Account, bobPhone, "bob", now); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "alice")
	if err != nil {
		t.Fatal(err)
	}
	caller := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	self := url.Values{"Action": {"ListMFADevices"}}
	named := url.Values{"Action": {"ListMFADevices"}, "UserName": {"alice"}}
	forBob := url.Values{"Action": {"ListMFADevices"}, "UserName": {"bob"}}
	put := func(policy string) {
		t.Helper()
		if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "alice", "list", policy); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("an Allow on the caller's own ARN lists the caller's devices", func(t *testing.T) {
		put(`{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"` + alice.ARN + `"}]}`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, self), http.StatusOK,
			`<UserName>alice</UserName>`, `<SerialNumber>`+alicePhone+`</SerialNumber>`)
		if want := "iam:ListMFADevices " + alice.ARN; len(rec.seen) == 0 || rec.seen[len(rec.seen)-1] != want {
			t.Errorf("authorized %v, want last %q", rec.seen, want)
		}
		has(t, call(t, h, caller, sigv4.ServiceIAM, named), http.StatusOK,
			`<SerialNumber>`+alicePhone+`</SerialNumber>`)
		res := call(t, h, caller, sigv4.ServiceIAM, forBob)
		has(t, res, http.StatusForbidden, `<Code>AccessDenied</Code>`)
		if strings.Contains(res.Body.String(), bobPhone) {
			t.Errorf("a denied call leaked another user's device: %s", res.Body.String())
		}
	})

	t.Run("a policy for a different user does not grant", func(t *testing.T) {
		put(`{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"` + bobUser.ARN + `"}]}`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, self), http.StatusForbidden, `<Code>AccessDenied</Code>`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, named), http.StatusForbidden, `<Code>AccessDenied</Code>`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, forBob), http.StatusOK,
			`<SerialNumber>`+bobPhone+`</SerialNumber>`)
	})

	t.Run("a Deny on the user's ARN refuses", func(t *testing.T) {
		put(`{"Statement":[{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"*"},` +
			`{"Effect":"Deny","Action":"iam:ListMFADevices","Resource":"` + alice.ARN + `"}]}`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, self), http.StatusForbidden, `<Code>AccessDenied</Code>`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, named), http.StatusForbidden, `<Code>AccessDenied</Code>`)
		has(t, call(t, h, caller, sigv4.ServiceIAM, forBob), http.StatusOK,
			`<SerialNumber>`+bobPhone+`</SerialNumber>`)
	})
}

// AWS validates UserName before it authorizes, so a malformed name is a 400
// even for a caller without iam:ListMFADevices, and nothing is authorized.
func TestListMFADevicesValidatesBeforeAuthorization(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	for _, name := range []string{"bad#name", strings.Repeat("a", 129), ""} {
		rec.seen = nil
		has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
			"Action": {"ListMFADevices"}, "UserName": {name},
		}), http.StatusBadRequest, `<Code>ValidationError</Code>`)
		if len(rec.seen) != 0 {
			t.Errorf("UserName %q authorized %v before validation", name, rec.seen)
		}
	}
}

// A user lookup that fails for a reason other than NoSuchEntity must not be
// authorized on a guessed ARN: alice is /restricted/alice, which bob may not
// list, so a check on user/alice would let bob through.
func TestListMFADevicesUnavailableLookupAuthorizesNothing(t *testing.T) {
	lookupErr := &resource.Error{Code: resource.CodeUnavailable, Message: "vws-iam is unavailable"}
	h, f, rec, root := harnessWith(t, func(a iam.Admin) iam.Admin {
		return userLookupError{Admin: a, err: lookupErr}
	})
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, root.Account, "alice", "/restricted/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	users := "arn:vws:iam::" + root.Account.String() + ":user/"
	policy := `{"Statement":[` +
		`{"Effect":"Allow","Action":"iam:ListMFADevices","Resource":"` + users + `alice"},` +
		`{"Effect":"Deny","Action":"iam:ListMFADevices","Resource":"` + users + `restricted/*"}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "list", policy); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
	rec.seen = nil
	has(t, call(t, h, bob, sigv4.ServiceIAM, url.Values{
		"Action": {"ListMFADevices"}, "UserName": {"alice"},
	}), http.StatusServiceUnavailable, `<Code>ServiceUnavailable</Code>`)
	if len(rec.seen) != 0 {
		t.Errorf("authorized on a guessed ARN: %v", rec.seen)
	}
}

// #330 r2: ListMFADevices lists the devices of the user the caller was
// authorized on. When the user moves to a denied path between the
// authorization and the read (a concurrent UpdateUser NewPath), the answer is
// 409 ConcurrentModification and no device. Without the move the same
// request succeeds, so the policy allows it.
func TestListMFADevicesActsOnTheAuthorizedARN(t *testing.T) {
	form := url.Values{"Action": {"ListMFADevices"}, "UserName": {"erin"}}
	seed := func(t *testing.T, f *iam.Fake, account resource.AccountID) string {
		t.Helper()
		serial := f.AddMfaDevice(account, "erin-phone")
		if err := f.AssignMfaDevice(account, serial, "erin", now); err != nil {
			t.Fatal(err)
		}
		return serial
	}
	t.Run("not moved", func(t *testing.T) {
		h, f, account, bob := authorizedARNHarness(t, nil)
		serial := seed(t, f, account)
		has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusOK, `<SerialNumber>`+serial+`</SerialNumber>`)
	})
	t.Run("moved after authorization", func(t *testing.T) {
		h, f, account, bob := authorizedARNHarness(t, &movingAdmin{user: "erin"})
		serial := seed(t, f, account)
		res := call(t, h, bob, sigv4.ServiceIAM, form)
		has(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
		if body := res.Body.String(); strings.Contains(body, serial) || strings.Contains(body, "<MFADevices>") {
			t.Errorf("a moved user's devices were answered: %s", body)
		}
		if u, err := f.GetUser(t.Context(), account, "erin"); err != nil || u.Path != "/denied/" {
			t.Fatalf("erin did not move: %+v, %v", u, err)
		}
	})
}
