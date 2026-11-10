package ec2query

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestMixedKindTagRequestWithAMissingIDWritesNothing sends CreateTags and
// DeleteTags naming existing resources of an earlier kind and a missing id
// of a later kind (#702). Each is answered with the later kind's NotFound
// and leaves every resource as it was, also when sent again.
func TestMixedKindTagRequestWithAMissingIDWritesNothing(t *testing.T) {
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
	vpc := xmlText(t, send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.9.0.0/16"}}), "vpcId")
	sub := xmlText(t, send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {"10.9.1.0/24"},
	}), "subnetId")
	inst := xmlText(t, send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {sub}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-mixed"},
	}), "instanceId")
	vol := xmlText(t, send(url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"8"},
	}), "volumeId")
	send(url.Values{
		"Action": {"CreateTags"}, "ResourceId.1": {inst}, "ResourceId.2": {vpc}, "ResourceId.3": {sub}, "ResourceId.4": {vol},
		"Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"},
	})
	describe := map[string]url.Values{
		vpc:  {"Action": {"DescribeVpcs"}, "VpcId.1": {vpc}},
		sub:  {"Action": {"DescribeSubnets"}, "SubnetId.1": {sub}},
		inst: {"Action": {"DescribeInstances"}, "InstanceId.1": {inst}},
		vol:  {"Action": {"DescribeVolumes"}, "VolumeId.1": {vol}},
	}
	const missingVpc, missingSub = "vpc-0fffffffffffffff0", "subnet-0fffffffffffffff0"
	const missingVol = "vol-0fffffffffffffff0"

	for name, tc := range map[string]struct {
		ids  []string
		code string
	}{
		"instance and a missing vpc":           {[]string{inst, missingVpc}, "InvalidVpcID.NotFound"},
		"vpc and a missing subnet":             {[]string{vpc, missingSub}, "InvalidSubnetID.NotFound"},
		"vpc, a subnet and a missing subnet":   {[]string{vpc, sub, missingSub}, "InvalidSubnetID.NotFound"},
		"instance, a vpc and a missing subnet": {[]string{inst, vpc, missingSub}, "InvalidSubnetID.NotFound"},
		"instance and a missing volume":        {[]string{inst, missingVol}, "InvalidVolume.NotFound"},
		"vpc and a missing volume":             {[]string{vpc, missingVol}, "InvalidVolume.NotFound"},
		"subnet and a missing volume":          {[]string{sub, missingVol}, "InvalidVolume.NotFound"},
		"instance, a vpc and a missing volume": {[]string{inst, vpc, missingVol}, "InvalidVolume.NotFound"},
		"vpc, a subnet and a missing volume":   {[]string{vpc, sub, missingVol}, "InvalidVolume.NotFound"},
		"vpc, a volume and a missing volume":   {[]string{vpc, vol, missingVol}, "InvalidVolume.NotFound"},
	} {
		for _, action := range []string{"CreateTags", "DeleteTags"} {
			if action == "DeleteTags" && tc.code == "InvalidVolume.NotFound" {
				continue
			}
			t.Run(action+"/"+name, func(t *testing.T) {
				send(url.Values{
					"Action": {"CreateTags"}, "ResourceId.1": {inst}, "ResourceId.2": {vpc},
					"ResourceId.3": {sub}, "ResourceId.4": {vol},
					"Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"},
				})
				f := url.Values{"Action": {action}, "Tag.1.Key": {"env"}}
				if action == "CreateTags" {
					f.Set("Tag.1.Value", "prod")
				}
				for i, id := range tc.ids {
					f.Set("ResourceId."+strconv.Itoa(i+1), id)
				}
				for range 2 {
					code, body := call(f)
					if code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+tc.code+"</Code>") {
						t.Fatalf("%s %s: %d %s", action, name, code, body)
					}
					for id, d := range describe {
						if got := send(d); !strings.Contains(got, "<key>env</key><value>dev</value>") {
							t.Fatalf("%s %s changed %s: %s", action, name, id, got)
						}
					}
				}
			})
		}
	}
}
