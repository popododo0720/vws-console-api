package ec2query

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const laptopKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1 me@laptop\n"

// #128: a user imports a key, launches with --key-name and --user-data, and
// reads both back the way the AWS CLI does.
func TestImportKeyLaunchAndUserData(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values, want int) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != want {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	for typ, header := range map[string]string{"": "BEGIN RSA PRIVATE KEY", "rsa": "BEGIN RSA PRIVATE KEY", "ed25519": "BEGIN OPENSSH PRIVATE KEY"} {
		f := url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"made-" + typ}}
		if typ != "" {
			f.Set("KeyType", typ)
		}
		if got := send(f, http.StatusOK); !strings.Contains(got, header) {
			t.Fatalf("KeyType %q: %s", typ, got)
		}
	}
	send(url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"ppk"}, "KeyFormat": {"ppk"}}, http.StatusBadRequest)
	send(url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"dsa"}, "KeyType": {"dsa"}}, http.StatusBadRequest)

	imported := send(url.Values{
		"Action": {"ImportKeyPair"}, "KeyName": {"laptop"},
		"PublicKeyMaterial": {base64.StdEncoding.EncodeToString([]byte(laptopKey))},
	}, http.StatusOK)
	if !strings.Contains(imported, "<ImportKeyPairResponse") || xmlText(t, imported, "keyName") != "laptop" || len(xmlText(t, imported, "keyFingerprint")) == 0 {
		t.Fatalf("import: %s", imported)
	}
	for _, junk := range []string{
		base64.StdEncoding.EncodeToString([]byte("not a key")),
		base64.StdEncoding.EncodeToString([]byte("ssh-dss AAAAB3NzaC1kc3M=")),
		"%%%",
	} {
		got := send(url.Values{"Action": {"ImportKeyPair"}, "KeyName": {"junk"}, "PublicKeyMaterial": {junk}}, http.StatusBadRequest)
		if !strings.Contains(got, "<Code>InvalidKey.Format</Code>") {
			t.Fatalf("malformed key %q: %s", junk, got)
		}
	}
	described := send(url.Values{"Action": {"DescribeKeyPairs"}, "KeyName.1": {"laptop"}}, http.StatusOK)
	if xmlText(t, described, "keyType") != "ed25519" {
		t.Fatalf("describe: %s", described)
	}

	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}}, http.StatusOK)
	subnet := send(url.Values{"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"}}, http.StatusOK)
	userData := "#cloud-config\nruncmd:\n  - touch /tmp/ok\n"
	launch := url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-key"},
		"KeyName": {"laptop"}, "UserData": {base64.StdEncoding.EncodeToString([]byte(userData))},
	}
	run := send(launch, http.StatusOK)
	id := xmlText(t, run, "instanceId")
	if xmlText(t, run, "keyName") != "laptop" {
		t.Fatalf("run: %s", run)
	}
	got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {id}}, http.StatusOK)
	if xmlText(t, got, "keyName") != "laptop" {
		t.Fatalf("describe instances: %s", got)
	}
	attr := send(url.Values{"Action": {"DescribeInstanceAttribute"}, "InstanceId": {id}, "Attribute": {"userData"}}, http.StatusOK)
	if xmlText(t, attr, "value") != base64.StdEncoding.EncodeToString([]byte(userData)) || xmlText(t, attr, "instanceId") != id {
		t.Fatalf("attribute: %s", attr)
	}

	bad := url.Values{}
	for k, v := range launch {
		bad[k] = v
	}
	bad.Set("ClientToken", "run-bad-ud")
	bad.Set("UserData", "%%%")
	send(bad, http.StatusBadRequest)
	bad.Set("ClientToken", "run-missing-key")
	bad.Del("UserData")
	bad.Set("KeyName", "nope")
	if got := send(bad, http.StatusBadRequest); !strings.Contains(got, "InvalidKeyPair.NotFound") {
		t.Fatalf("missing key: %s", got)
	}
}
