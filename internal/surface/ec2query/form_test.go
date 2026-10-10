package ec2query

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestUnsupportedFilterIsRejected(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "DescribeInstances")
	form.Set("Version", Version)
	form.Set("Filter.1.Name", "vpc-id")
	form.Set("Filter.1.Value.1", "vpc-1")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidParameterValue") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func TestClientTokenIsRequired(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "RunInstances")
	form.Set("Version", Version)
	form.Set("ImageId", "ami-0123456789abcdef0")
	form.Set("InstanceType", "vws.small")
	form.Set("SubnetId", "subnet-0123456789abcdef0")
	form.Set("MinCount", "1")
	form.Set("MaxCount", "1")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "ClientToken") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func TestUnreadQueryFieldsAreRejected(t *testing.T) {
	h, cred, now := harness(t)
	vpc := url.Values{}
	vpc.Set("Action", "CreateVpc")
	vpc.Set("Version", Version)
	vpc.Set("CidrBlock", "10.1.0.0/16")
	vpc.Set("TagSpecification.1.ResourceType", "vpc")
	vpc.Set("TagSpecification.1.Tag.1.Key", "Name")
	vpc.Set("TagSpecification.1.Tag.1.Value", "web")
	res := signed(t, h, cred, now, vpc.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidParameterValue") {
		t.Fatalf("tag spec %d %s", res.Code, res.Body)
	}
	vpc.Del("TagSpecification.1.ResourceType")
	vpc.Del("TagSpecification.1.Tag.1.Key")
	vpc.Del("TagSpecification.1.Tag.1.Value")
	res = signed(t, h, cred, now, vpc.Encode())
	if res.Code != http.StatusOK {
		t.Fatalf("vpc without tags %d %s", res.Code, res.Body)
	}
	auth := url.Values{}
	auth.Set("Action", "AuthorizeSecurityGroupIngress")
	auth.Set("Version", Version)
	auth.Set("GroupId", "sg-01234567")
	auth.Set("IpPermissions.1.IpProtocol", "tcp")
	auth.Set("IpPermissions.1.FromPort", "22")
	auth.Set("IpPermissions.1.ToPort", "22")
	auth.Set("IpPermissions.1.IpRanges.1.CidrIp", "10.0.0.0/16")
	auth.Set("IpPermissions.2.IpProtocol", "udp")
	res = signed(t, h, cred, now, auth.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidParameterValue") {
		t.Fatalf("second permission %d %s", res.Code, res.Body)
	}
	auth.Del("IpPermissions.2.IpProtocol")
	res = signed(t, h, cred, now, auth.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidGroup.NotFound") {
		t.Fatalf("one permission %d %s", res.Code, res.Body)
	}
}

func TestStopOmitsClientToken(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "StopInstances")
	form.Set("Version", Version)
	form.Set("InstanceId.1", "i-01234567")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest || strings.Contains(res.Body.String(), "ClientToken") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if !strings.Contains(res.Body.String(), "InvalidInstanceID.NotFound") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func TestIndexPastTheCapIsRejected(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "StopInstances")
	form.Set("Version", Version)
	form.Set("ClientToken", "stop-1")
	form.Set("InstanceId.1", "i-01234567")
	form.Set("InstanceId.101", "i-89abcdef")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func harness(t *testing.T) (http.Handler, sigv4.Credential, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	h := New(Config{Service: svc, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceEC2,
		Region:  resource.RegionName,
		Now:     func() time.Time { return now },
		Lookup: func(_ context.Context, key string) (sigv4.Credential, bool) {
			return cred, key == cred.AccessKey
		},
	})})
	return h, cred, now
}

func signed(t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader(body))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
