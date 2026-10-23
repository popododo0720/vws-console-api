package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDetachVolumeThenDelete(t *testing.T) {
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
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.4.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.4.1.0/24"},
	})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-detach"},
	})
	inst := xmlText(t, run, "instanceId")
	created := send(url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"4"}, "ClientToken": {"vol-detach"},
	})
	vol := xmlText(t, created, "volumeId")
	send(url.Values{"Action": {"AttachVolume"}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"}})
	mismatch := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdg"},
	}.Encode())
	if got := ec2ErrorXML(t, mismatch.Body.Bytes()); mismatch.Code != http.StatusBadRequest ||
		got.Code != "InvalidAttachment.NotFound" ||
		got.Message != "The volume '"+vol+"' is not attached to the instance." {
		t.Fatalf("device mismatch %d %+v", mismatch.Code, got)
	}
	body := send(url.Values{
		"Action": {"DetachVolume"}, "VolumeId": {vol}, "InstanceId": {inst},
		"Device": {"/dev/sdf"}, "ClientToken": {"detach-1"},
	})
	for _, want := range []string{
		"<volumeId>" + vol + "</volumeId>",
		"<instanceId>" + inst + "</instanceId>",
		"<device>/dev/sdf</device>",
		"<status>detaching</status>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("no %s in %s", want, body)
		}
	}
	attachTimeOK(t, body)
	reused := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {vol}, "InstanceId": {inst},
		"Device": {"/dev/sdg"}, "ClientToken": {"detach-1"},
	}.Encode())
	if got := ec2ErrorXML(t, reused.Body.Bytes()); reused.Code != http.StatusBadRequest ||
		got.Code != "IdempotentParameterMismatch" ||
		got.Message != "Arguments on this idempotent request are inconsistent with arguments used in previous request(s)." {
		t.Fatalf("reused token %d %+v", reused.Code, got)
	}
	again := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"},
	}.Encode())
	if got := ec2ErrorXML(t, again.Body.Bytes()); again.Code != http.StatusBadRequest ||
		got.Code != "IncorrectState" ||
		got.Message != "Volume '"+vol+"' is in the 'available' state." {
		t.Fatalf("second detach %d %+v", again.Code, got)
	}
	send(url.Values{"Action": {"DeleteVolume"}, "VolumeId": {vol}})
	missing := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {"vol-0123456789abcdef0"},
	}.Encode())
	if got := ec2ErrorXML(t, missing.Body.Bytes()); missing.Code != http.StatusBadRequest ||
		got.Code != "InvalidVolume.NotFound" ||
		got.Message != "The volume 'vol-0123456789abcdef0' does not exist." {
		t.Fatalf("missing %d %+v", missing.Code, got)
	}
	described := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeVolumes"}, "Version": {Version}, "VolumeId.1": {vol},
	}.Encode())
	if got := ec2ErrorXML(t, described.Body.Bytes()); described.Code != http.StatusBadRequest ||
		got.Code != "InvalidVolume.NotFound" ||
		got.Message != "The volume '"+vol+"' does not exist." {
		t.Fatalf("describe a deleted volume %d %+v", described.Code, got)
	}
}
