package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestDeleteTags follows EC2 DeleteTags: a key alone deletes the tag whatever
// its value, a key with a value (the empty string included) only on a match,
// no Tag.N deletes every tag, and a tag the resource lacks is not an error.
func TestDeleteTags(t *testing.T) {
	h, cred, now := harness(t)
	call := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	send := func(f url.Values) string {
		t.Helper()
		code, body := call(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	tagSpec := func(kind string) url.Values {
		return url.Values{
			"TagSpecification.1.ResourceType": {kind},
			"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"web"},
			"TagSpecification.1.Tag.2.Key": {"env"}, "TagSpecification.1.Tag.2.Value": {"dev"},
			"TagSpecification.1.Tag.3.Key": {"blank"}, "TagSpecification.1.Tag.3.Value": {""},
			"TagSpecification.1.Tag.4.Key": {"team"}, "TagSpecification.1.Tag.4.Value": {"sre"},
		}
	}
	with := func(base url.Values, more url.Values) url.Values {
		for k, v := range more {
			base[k] = v
		}
		return base
	}
	vpcForm := url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}}
	vpc := xmlText(t, send(with(vpcForm, tagSpec("vpc"))), "vpcId")
	subForm := url.Values{"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {"10.0.1.0/24"}}
	sub := xmlText(t, send(with(subForm, tagSpec("subnet"))), "subnetId")
	inst := xmlText(t, send(with(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {sub}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-untag"},
	}, tagSpec("instance"))), "instanceId")
	describe := map[string]url.Values{
		vpc:  {"Action": {"DescribeVpcs"}, "VpcId.1": {vpc}},
		sub:  {"Action": {"DescribeSubnets"}, "SubnetId.1": {sub}},
		inst: {"Action": {"DescribeInstances"}, "InstanceId.1": {inst}},
	}
	tagSet := func(id string) string {
		t.Helper()
		body := send(describe[id])
		i := strings.Index(body, "<tagSet>")
		if i < 0 {
			return ""
		}
		return body[i : strings.Index(body, "</tagSet>")+len("</tagSet>")]
	}

	got := send(url.Values{
		"Action": {"DeleteTags"}, "ResourceId.1": {vpc}, "ResourceId.2": {sub}, "ResourceId.3": {inst},
		"Tag.1.Key": {"Name"},
		"Tag.2.Key": {"env"}, "Tag.2.Value": {"prod"},
		"Tag.3.Key": {"blank"}, "Tag.3.Value": {""},
		"Tag.4.Key": {"absent"},
	})
	if !strings.Contains(got, "<DeleteTagsResponse") || !strings.Contains(got, "<return>true</return>") {
		t.Fatalf("response %s", got)
	}
	want := "<tagSet><item><key>env</key><value>dev</value></item><item><key>team</key><value>sre</value></item></tagSet>"
	for _, id := range []string{vpc, sub, inst} {
		if got := tagSet(id); got != want {
			t.Fatalf("%s tags after DeleteTags: %s", id, got)
		}
	}

	// The same request again changes nothing and still succeeds.
	send(url.Values{"Action": {"DeleteTags"}, "ResourceId.1": {vpc}, "Tag.1.Key": {"Name"}})
	if got := tagSet(vpc); got != want {
		t.Fatalf("vpc tags after a repeated DeleteTags: %s", got)
	}

	// Key and matching value deletes the tag.
	send(url.Values{"Action": {"DeleteTags"}, "ResourceId.1": {sub}, "Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"}})
	if got := tagSet(sub); got != "<tagSet><item><key>team</key><value>sre</value></item></tagSet>" {
		t.Fatalf("subnet tags after a matching delete: %s", got)
	}

	// No Tag.N deletes every tag.
	send(url.Values{"Action": {"DeleteTags"}, "ResourceId.1": {inst}})
	if got := tagSet(inst); strings.Contains(got, "<item>") {
		t.Fatalf("instance tags after deleting all: %s", got)
	}

	for name, tc := range map[string]struct {
		form url.Values
		code string
	}{
		"missing vpc":       {url.Values{"ResourceId.1": {"vpc-0fffffffffffffff0"}}, "InvalidVpcID.NotFound"},
		"missing subnet":    {url.Values{"ResourceId.1": {"subnet-0fffffffffffffff0"}}, "InvalidSubnetID.NotFound"},
		"missing instance":  {url.Values{"ResourceId.1": {"i-0fffffffffffffff0"}}, "InvalidInstanceID.NotFound"},
		"no resource":       {url.Values{"Tag.1.Key": {"env"}}, "InvalidParameterValue"},
		"unsupported kind":  {url.Values{"ResourceId.1": {"sg-0123456789abcdef0"}}, "InvalidParameterValue"},
		"value without key": {url.Values{"ResourceId.1": {vpc}, "Tag.1.Value": {"dev"}}, "InvalidParameterValue"},
		"aws: key":          {url.Values{"ResourceId.1": {vpc}, "Tag.1.Key": {"aws:stack"}}, "InvalidParameterValue"},
		"client token":      {url.Values{"ResourceId.1": {vpc}, "ClientToken": {"t-1"}}, "InvalidParameterValue"},
	} {
		tc.form.Set("Action", "DeleteTags")
		code, body := call(tc.form)
		if code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+tc.code+"</Code>") {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	// A failed request leaves the tags as they were.
	if got := tagSet(vpc); got != want {
		t.Fatalf("vpc tags after failed deletes: %s", got)
	}
}

// TestFannedOutTagRequestIsCheckedBeforeAnyWrite sends CreateTags and
// DeleteTags whose later kind fails validation (a repeated subnet id). The
// request is refused, and the earlier kind keeps its tags.
func TestFannedOutTagRequestIsCheckedBeforeAnyWrite(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	ok := func(f url.Values) string {
		t.Helper()
		code, body := send(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	vpc := xmlText(t, ok(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}}), "vpcId")
	sub := xmlText(t, ok(url.Values{"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {"10.0.1.0/24"}}), "subnetId")
	ok(url.Values{"Action": {"CreateTags"}, "ResourceId.1": {vpc}, "Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"}})
	for _, f := range []url.Values{
		{
			"Action": {"CreateTags"}, "ResourceId.1": {vpc}, "ResourceId.2": {sub}, "ResourceId.3": {sub},
			"Tag.1.Key": {"env"}, "Tag.1.Value": {"prod"},
		},
		{"Action": {"DeleteTags"}, "ResourceId.1": {vpc}, "ResourceId.2": {sub}, "ResourceId.3": {sub}, "Tag.1.Key": {"env"}},
	} {
		if code, body := send(f); code != http.StatusBadRequest {
			t.Fatalf("%s with a repeated subnet id: %d %s", f.Get("Action"), code, body)
		}
		got := ok(url.Values{"Action": {"DescribeVpcs"}, "VpcId.1": {vpc}})
		if !strings.Contains(got, "<key>env</key><value>dev</value>") {
			t.Fatalf("a refused %s changed the vpc tags: %s", f.Get("Action"), got)
		}
	}
}

// TestAWSTagKeysCannotBeSet checks that CreateTags refuses an aws: key, as
// EC2 does. DeleteTags cannot name one either, so a key CreateTags let
// through could never be removed.
func TestAWSTagKeysCannotBeSet(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	_, created := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	vpc := xmlText(t, created, "vpcId")
	for _, key := range []string{"aws:stack", "AWS:stack"} {
		code, body := send(url.Values{
			"Action": {"CreateTags"}, "ResourceId.1": {vpc}, "Tag.1.Key": {key}, "Tag.1.Value": {"x"},
		})
		if code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidParameterValue</Code>") {
			t.Fatalf("CreateTags %s: %d %s", key, code, body)
		}
	}
	_, got := send(url.Values{"Action": {"DescribeVpcs"}, "VpcId.1": {vpc}})
	if strings.Contains(strings.ToLower(got), "<key>aws:stack</key>") {
		t.Fatalf("a refused CreateTags set an aws: tag: %s", got)
	}
}
