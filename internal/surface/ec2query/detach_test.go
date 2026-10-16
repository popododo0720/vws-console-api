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
	if mismatch.Code != http.StatusBadRequest ||
		!strings.Contains(mismatch.Body.String(), "<Code>InvalidAttachment.NotFound</Code>") {
		t.Fatalf("device mismatch %d %s", mismatch.Code, mismatch.Body)
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
	again := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"},
	}.Encode())
	if again.Code != http.StatusBadRequest || !strings.Contains(again.Body.String(), "<Code>IncorrectState</Code>") {
		t.Fatalf("second detach %d %s", again.Code, again.Body)
	}
	send(url.Values{"Action": {"DeleteVolume"}, "VolumeId": {vol}})
	missing := signed(t, h, cred, now, url.Values{
		"Action": {"DetachVolume"}, "Version": {Version}, "VolumeId": {"vol-0123456789abcdef0"},
	}.Encode())
	if missing.Code != http.StatusBadRequest ||
		!strings.Contains(missing.Body.String(), "<Code>InvalidVolume.NotFound</Code>") {
		t.Fatalf("missing %d %s", missing.Code, missing.Body)
	}
}
