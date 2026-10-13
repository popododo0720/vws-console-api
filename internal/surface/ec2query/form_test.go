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

func TestCreateSubnetOmitsClientToken(t *testing.T) {
	h, cred, now := harness(t)
	first := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "Version": {Version}, "CidrBlock": {"10.7.1.0/24"},
	}.Encode())
	if first.Code != http.StatusOK || strings.Contains(first.Body.String(), "ClientToken") {
		t.Fatalf("%d %s", first.Code, first.Body)
	}
	id := subnetIDOf(t, first.Body.String())
	again := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "Version": {Version}, "CidrBlock": {"10.7.1.0/24"},
	}.Encode())
	if again.Code != http.StatusOK || subnetIDOf(t, again.Body.String()) != id {
		t.Fatalf("retry %d %s", again.Code, again.Body)
	}
	other := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "Version": {Version}, "CidrBlock": {"10.7.2.0/24"},
	}.Encode())
	if other.Code != http.StatusOK || subnetIDOf(t, other.Body.String()) == id {
		t.Fatalf("distinct %d %s", other.Code, other.Body)
	}
	deleted := signed(t, h, cred, now, url.Values{
		"Action": {"DeleteSubnet"}, "Version": {Version}, "SubnetId": {id},
	}.Encode())
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body)
	}
	recreated := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "Version": {Version}, "CidrBlock": {"10.7.1.0/24"},
	}.Encode())
	if recreated.Code != http.StatusOK || subnetIDOf(t, recreated.Body.String()) == id {
		t.Fatalf("recreate %d %s", recreated.Code, recreated.Body)
	}
}

func TestDescribeSecurityGroupReturnsRules(t *testing.T) {
	h, cred, now := harness(t)
	vpc := signed(t, h, cred, now, url.Values{
		"Action": {"CreateVpc"}, "Version": {Version}, "CidrBlock": {"10.7.0.0/16"},
	}.Encode())
	if vpc.Code != http.StatusOK {
		t.Fatalf("vpc %d %s", vpc.Code, vpc.Body)
	}
	group := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSecurityGroup"}, "Version": {Version},
		"GroupName": {"web"}, "GroupDescription": {"web"}, "VpcId": {xmlText(t, vpc.Body.String(), "vpcId")},
	}.Encode())
	if group.Code != http.StatusOK {
		t.Fatalf("group %d %s", group.Code, group.Body)
	}
	opened := signed(t, h, cred, now, url.Values{
		"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version},
		"GroupId":    {xmlText(t, group.Body.String(), "groupId")},
		"IpProtocol": {"tcp"}, "FromPort": {"22"}, "ToPort": {"22"}, "CidrIp": {"10.0.0.0/16"},
	}.Encode())
	if opened.Code != http.StatusOK {
		t.Fatalf("authorize %d %s", opened.Code, opened.Body)
	}
	described := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSecurityGroups"}, "Version": {Version},
		"GroupId.1": {xmlText(t, group.Body.String(), "groupId")},
	}.Encode())
	if described.Code != http.StatusOK || !strings.Contains(described.Body.String(), "<cidrIp>10.0.0.0/16</cidrIp>") {
		t.Fatalf("describe %d %s", described.Code, described.Body)
	}
}

func subnetIDOf(t *testing.T, body string) string {
	t.Helper()
	return xmlText(t, body, "subnetId")
}

func xmlText(t *testing.T, body, tag string) string {
	t.Helper()
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(body, open)
	end := strings.Index(body, closeTag)
	if start < 0 || end < start {
		t.Fatalf("no %s in %s", tag, body)
	}
	return body[start+len(open) : end]
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

func TestStopRunningInstanceWithoutClientToken(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"}})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-1"},
	})
	stopped := send(url.Values{"Action": {"StopInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
	if !strings.Contains(stopped, "<name>stopping</name>") {
		t.Fatalf("%s", stopped)
	}
}

func TestCatalogActionsAreImplemented(t *testing.T) {
	h, cred, now := harness(t)
	for _, action := range []string{"DescribeKeyPairs", "DescribeSecurityGroups", "DescribeAddresses", "DescribeSnapshots"} {
		res := signed(t, h, cred, now, url.Values{"Action": {action}, "Version": {Version}}.Encode())
		if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
	}
	for _, action := range []string{"DeleteKeyPair", "DeleteSecurityGroup", "DeleteSubnet", "ReleaseAddress", "CreateSnapshot", "DeleteSnapshot"} {
		res := signed(t, h, cred, now, url.Values{"Action": {action}, "Version": {Version}}.Encode())
		if res.Code == http.StatusNotImplemented || strings.Contains(res.Body.String(), "InvalidAction") {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
		if res.Code != http.StatusBadRequest {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
	}
	allocated := signed(t, h, cred, now, url.Values{"Action": {"AllocateAddress"}, "Version": {Version}}.Encode())
	if allocated.Code != http.StatusOK || !strings.Contains(allocated.Body.String(), "<allocationId>") || strings.Contains(allocated.Body.String(), "InvalidAction") {
		t.Fatalf("allocate %d %s", allocated.Code, allocated.Body)
	}
}

func TestDescribeStandardParameters(t *testing.T) {
	h, cred, now := harness(t)
	created := signed(t, h, cred, now, url.Values{
		"Action": {"CreateVolume"}, "Version": {Version}, "Size": {"8"}, "AvailabilityZone": {resource.ZoneName},
	}.Encode())
	if created.Code != http.StatusOK {
		t.Fatalf("volume %d %s", created.Code, created.Body)
	}
	volumeID := xmlText(t, created.Body.String(), "volumeId")
	snap := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSnapshot"}, "Version": {Version}, "VolumeId": {volumeID},
	}.Encode())
	if snap.Code != http.StatusOK {
		t.Fatalf("snapshot %d %s", snap.Code, snap.Body)
	}
	snapshotID := xmlText(t, snap.Body.String(), "snapshotId")
	self := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSnapshots"}, "Version": {Version}, "Owner.1": {"self"},
	}.Encode())
	if self.Code != http.StatusOK || !strings.Contains(self.Body.String(), snapshotID) {
		t.Fatalf("owner self %d %s", self.Code, self.Body)
	}
	ownerID := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSnapshots"}, "Version": {Version}, "OwnerId.1": {"self"},
	}.Encode())
	if ownerID.Code != http.StatusOK || !strings.Contains(ownerID.Body.String(), snapshotID) {
		t.Fatalf("ownerId self %d %s", ownerID.Code, ownerID.Body)
	}
	other := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSnapshots"}, "Version": {Version}, "Owner.1": {"000000000000"},
	}.Encode())
	if other.Code != http.StatusOK || strings.Contains(other.Body.String(), snapshotID) {
		t.Fatalf("other owner %d %s", other.Code, other.Body)
	}
	images := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeImages"}, "Version": {Version}, "Owner.1": {"self"}, "IncludeDeprecated": {"false"},
	}.Encode())
	if images.Code != http.StatusOK || !strings.Contains(images.Body.String(), "ami-0123456789abcdef0") {
		t.Fatalf("images %d %s", images.Code, images.Body)
	}
	foreign := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeImages"}, "Version": {Version}, "ExecutableBy.1": {"000000000000"},
	}.Encode())
	if foreign.Code != http.StatusOK || strings.Contains(foreign.Body.String(), "ami-0123456789abcdef0") {
		t.Fatalf("executable %d %s", foreign.Code, foreign.Body)
	}
	paged := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeVolumes"}, "Version": {Version}, "maxResults": {"5"},
	}.Encode())
	if paged.Code != http.StatusOK || !strings.Contains(paged.Body.String(), volumeID) {
		t.Fatalf("volumes %d %s", paged.Code, paged.Body)
	}
	dry := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSnapshots"}, "Version": {Version}, "dryRun": {"true"},
	}.Encode())
	if dry.Code != http.StatusBadRequest {
		t.Fatalf("dry run %d %s", dry.Code, dry.Body)
	}
	keys := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeKeyPairs"}, "Version": {Version}, "IncludePublicKey": {"true"},
	}.Encode())
	if keys.Code != http.StatusOK {
		t.Fatalf("keys %d %s", keys.Code, keys.Body)
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

func TestVolumeTypeRoundTrips(t *testing.T) {
	h, cred, now := harness(t)
	for _, want := range []string{"standard", "gp2", "gp3"} {
		form := url.Values{}
		form.Set("Action", "CreateVolume")
		form.Set("Version", Version)
		form.Set("AvailabilityZone", "vws-1a")
		form.Set("Size", "1")
		form.Set("VolumeType", want)
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<volumeType>"+want+"</volumeType>") {
			t.Fatalf("create %s: %d %s", want, res.Code, res.Body)
		}
		id := between(res.Body.String(), "<volumeId>", "</volumeId>")
		desc := url.Values{}
		desc.Set("Action", "DescribeVolumes")
		desc.Set("Version", Version)
		desc.Set("VolumeId.1", id)
		res = signed(t, h, cred, now, desc.Encode())
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<volumeType>"+want+"</volumeType>") {
			t.Fatalf("describe %s: %d %s", want, res.Code, res.Body)
		}
	}
}

func TestCreateVolumeDefaultsToGP2(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "CreateVolume")
	form.Set("Version", Version)
	form.Set("AvailabilityZone", "vws-1a")
	form.Set("Size", "1")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<volumeType>gp2</volumeType>") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func TestDescribeVolumesHasCreateTime(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{}
	form.Set("Action", "CreateVolume")
	form.Set("Version", Version)
	form.Set("AvailabilityZone", "vws-1a")
	form.Set("Size", "1")
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK || between(res.Body.String(), "<createTime>", "</createTime>") == "" {
		t.Fatalf("create: %d %s", res.Code, res.Body)
	}
	desc := url.Values{}
	desc.Set("Action", "DescribeVolumes")
	desc.Set("Version", Version)
	desc.Set("VolumeId.1", between(res.Body.String(), "<volumeId>", "</volumeId>"))
	res = signed(t, h, cred, now, desc.Encode())
	got := between(res.Body.String(), "<createTime>", "</createTime>")
	if res.Code != http.StatusOK || got == "" {
		t.Fatalf("describe: %d %s", res.Code, res.Body)
	}
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("createTime %q: %v", got, err)
	}
}

func between(s, open, close string) string {
	_, rest, _ := strings.Cut(s, open)
	out, _, _ := strings.Cut(rest, close)
	return out
}

func TestDescribeAcceptsCLIDefaultMaxResults(t *testing.T) {
	h, cred, now := harness(t)
	for _, action := range []string{"DescribeVolumes", "DescribeInstances", "DescribeSnapshots"} {
		form := url.Values{}
		form.Set("Action", action)
		form.Set("Version", Version)
		form.Set("MaxResults", "1000")
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
	}
}

func TestCreateVolumeFromSnapshot(t *testing.T) {
	h, cred, now := harness(t)
	call := func(kv ...string) (int, string) {
		form := url.Values{}
		form.Set("Version", Version)
		for i := 0; i < len(kv); i += 2 {
			form.Set(kv[i], kv[i+1])
		}
		res := signed(t, h, cred, now, form.Encode())
		return res.Code, res.Body.String()
	}
	code, body := call("Action", "CreateVolume", "AvailabilityZone", "vws-1a", "Size", "3")
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	code, body = call("Action", "CreateSnapshot", "VolumeId", between(body, "<volumeId>", "</volumeId>"))
	if code != http.StatusOK {
		t.Fatalf("snapshot: %d %s", code, body)
	}
	snap := between(body, "<snapshotId>", "</snapshotId>")
	code, body = call("Action", "CreateVolume", "AvailabilityZone", "vws-1a", "SnapshotId", snap)
	if code != http.StatusOK || between(body, "<snapshotId>", "</snapshotId>") != snap || between(body, "<size>", "</size>") != "3" {
		t.Fatalf("restore: %d %s", code, body)
	}
	code, body = call("Action", "DescribeVolumes", "VolumeId.1", between(body, "<volumeId>", "</volumeId>"))
	if code != http.StatusOK || between(body, "<snapshotId>", "</snapshotId>") != snap {
		t.Fatalf("describe: %d %s", code, body)
	}
	code, body = call("Action", "CreateVolume", "AvailabilityZone", "vws-1a", "SnapshotId", "snap-00000000000000000")
	if code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidSnapshot.NotFound</Code>") {
		t.Fatalf("missing snapshot: %d %s", code, body)
	}
}
