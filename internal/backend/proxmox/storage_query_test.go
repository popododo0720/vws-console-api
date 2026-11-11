package proxmox

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func storageQuery(
	t *testing.T, set backend.Set, caps backend.Capabilities,
) func(url.Values) *httptest.ResponseRecorder {
	t.Helper()
	cred := sigv4.Credential{AccessKey: "AKID", Secret: "secret", Account: inventoryScope().Account}
	now := time.Now().UTC()
	auth := iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)
	h := ec2query.New(ec2query.Config{
		Service: cloud.New(cloud.Config{Backends: set, Capabilities: caps}), Authorizer: auth,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
			Now: func() time.Time { return now }, Auth: iam.Authenticator(auth),
		}),
	})
	return func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		form.Set("Version", ec2query.Version)
		r := httptest.NewRequestWithContext(t.Context(),
			http.MethodPost, "http://localhost/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sigv4.Sign(r, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		t.Logf("%s: HTTP %d %s", form.Get("Action"), w.Code, w.Body)
		return w
	}
}

func TestPVEStorageQuery(t *testing.T) {
	b, _ := networkBackend(t, volumeScenario(), RegionConfig{})
	call := storageQuery(t, b.Set(), b)
	for _, tc := range []struct {
		form   url.Values
		status int
		want   string
	}{
		{url.Values{"Action": {"DescribeVolumes"}}, 200, "<volumeId>vol-0123456789abcdef0</volumeId>"},
		{url.Values{"Action": {"DescribeSnapshots"}}, 200, "<volumeSize>8</volumeSize>"},
		{
			url.Values{"Action": {"DescribeTags"}, "Filter.1.Name": {"resource-type"}, "Filter.1.Value.1": {"snapshot"}},
			200, "<value>backup</value>",
		},
		{url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {"vol-fffffffffffffffff"}}, 400, "InvalidVolume.NotFound"},
		{
			url.Values{"Action": {"DescribeVolumes"}, "Filter.1.Name": {"unknown"}, "Filter.1.Value.1": {"x"}},
			400, "InvalidParameterValue",
		},
		{
			url.Values{"Action": {"DescribeTags"}, "Filter.01.Name": {"key"}, "Filter.01.Value.1": {"Name"}},
			400, "InvalidParameterValue",
		},
	} {
		w := call(tc.form)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) ||
			strings.Contains(w.Body.String(), "foreign") {
			t.Fatalf("response: %d %s", w.Code, w.Body)
		}
	}
}

func TestDescribeTagsSharedFilters(t *testing.T) {
	for _, name := range []string{"fake", "proxmox"} {
		t.Run(name, func(t *testing.T) {
			var call func(url.Values) *httptest.ResponseRecorder
			id := "vol-0123456789abcdef0"
			if name == "proxmox" {
				b, _ := networkBackend(t, volumeScenario(), RegionConfig{})
				call = storageQuery(t, b.Set(), b)
			} else {
				w := fake.New(fake.Options{})
				set := w.Set()
				created, err := set.Compute.CreateVolume(t.Context(), backend.Mutation{
					Scope: inventoryScope(), Key: "root", Fingerprint: "root",
				}, resource.CreateVolumeRequest{
					SizeGiB: 8, Type: resource.VolumeGP2, Zone: "vws-1a", Tags: map[string]string{"Name": "root"},
				})
				if err != nil {
					t.Fatal(err)
				}
				id = created.Items[0].ID.String()
				call = storageQuery(t, set, nil)
			}
			for _, tc := range []struct {
				key, value string
				want       bool
			}{
				{"resource-id", id, true},
				{"resource-id", "vol-fffffffffffffffff", false},
				{"resource-id", "vol-*", true},
				{"key", "Name", true},
				{"key", "N*", true},
				{"key", "missing", false},
			} {
				w := call(url.Values{
					"Action": {"DescribeTags"}, "Filter.1.Name": {"resource-type"}, "Filter.1.Value.1": {"volume"},
					"Filter.2.Name": {tc.key}, "Filter.2.Value.1": {tc.value},
					"Filter.3.Name": {"value"}, "Filter.3.Value.1": {"root"},
				})
				var response struct {
					Tags []struct {
						ID  string `xml:"resourceId"`
						Key string `xml:"key"`
					} `xml:"tagSet>item"`
				}
				if err := xml.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, tag := range response.Tags {
					found = found || tag.ID == id && tag.Key == "Name"
				}
				if w.Code != 200 || found != tc.want {
					t.Fatalf("%s=%s: %d %s", tc.key, tc.value, w.Code, w.Body)
				}
			}
		})
	}
}
