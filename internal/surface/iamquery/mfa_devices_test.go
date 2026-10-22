package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
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
