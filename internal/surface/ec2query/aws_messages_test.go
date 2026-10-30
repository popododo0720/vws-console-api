package ec2query

import (
	"net/http"
	"net/url"
	"testing"
)

// #243: each not-found answer carries the AWS sentence for its code and names
// the id the caller sent. The patterns are the ones vws-conformance checks
// against the EC2 errors page.
func TestNotFoundMessagesMatchAWS(t *testing.T) {
	for _, tc := range []struct {
		action string
		param  string
		value  string
		extra  url.Values
		code   string
		want   string
	}{
		{
			action: "DescribeInstances", param: "InstanceId.1", value: "i-0123456789abcdef0",
			code: "InvalidInstanceID.NotFound",
			want: "The instance ID 'i-0123456789abcdef0' does not exist",
		},
		{
			action: "DescribeInstanceAttribute", param: "InstanceId", value: "i-0123456789abcdef0",
			extra: url.Values{"Attribute": {"userData"}},
			code:  "InvalidInstanceID.NotFound",
			want:  "The instance ID 'i-0123456789abcdef0' does not exist",
		},
		{
			action: "DescribeImages", param: "ImageId.1", value: "ami-0123456789abcdef1",
			code: "InvalidAMIID.NotFound",
			want: "The image id '[ami-0123456789abcdef1]' does not exist",
		},
		{
			action: "DescribeKeyPairs", param: "KeyName.1", value: "conf-missing",
			code: "InvalidKeyPair.NotFound",
			want: "The key pair 'conf-missing' does not exist",
		},
		{
			action: "DescribeAddresses", param: "AllocationId.1", value: "eipalloc-0123456789abcdef0",
			code: "InvalidAllocationID.NotFound",
			want: "The allocation ID 'eipalloc-0123456789abcdef0' does not exist",
		},
		{
			action: "DescribeVolumes", param: "VolumeId.1", value: "vol-0123456789abcdef0",
			code: "InvalidVolume.NotFound",
			want: "The volume 'vol-0123456789abcdef0' does not exist.",
		},
		{
			action: "DescribeSnapshots", param: "SnapshotId.1", value: "snap-0123456789abcdef0",
			code: "InvalidSnapshot.NotFound",
			want: "The snapshot 'snap-0123456789abcdef0' does not exist.",
		},
		{
			action: "DescribeVpcs", param: "VpcId.1", value: "vpc-0123456789abcdef0",
			code: "InvalidVpcID.NotFound",
			want: "The vpc ID 'vpc-0123456789abcdef0' does not exist",
		},
		{
			action: "DescribeSubnets", param: "SubnetId.1", value: "subnet-0123456789abcdef0",
			code: "InvalidSubnetID.NotFound",
			want: "The subnet ID 'subnet-0123456789abcdef0' does not exist",
		},
		{
			action: "DescribeSecurityGroups", param: "GroupId.1", value: "sg-0123456789abcdef0",
			code: "InvalidGroup.NotFound",
			want: "The security group 'sg-0123456789abcdef0' does not exist",
		},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h, cred, now := harness(t)
			form := url.Values{}
			form.Set("Action", tc.action)
			form.Set("Version", Version)
			form.Set(tc.param, tc.value)
			for key, values := range tc.extra {
				for _, value := range values {
					form.Add(key, value)
				}
			}
			res := signed(t, h, cred, now, form.Encode())
			if res.Code != http.StatusBadRequest {
				t.Fatalf("status %d body %s", res.Code, res.Body)
			}
			got := ec2ErrorXML(t, res.Body.Bytes())
			if got.Code != tc.code || got.Message != tc.want {
				t.Fatalf("code %q message %q, want %q %q", got.Code, got.Message, tc.code, tc.want)
			}
		})
	}
}
