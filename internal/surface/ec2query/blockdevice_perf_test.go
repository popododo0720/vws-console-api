package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// #324 AC1: BlockDeviceMapping.N.Ebs.Iops and Ebs.Throughput on the root
// device follow the EbsBlockDevice rules of the EC2 API Reference (the same
// per-type rules as CreateVolume) on the 8 GiB root volume, and
// DescribeVolumes returns the values the root volume got.
func TestRunInstancesRootIopsAndThroughput(t *testing.T) {
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
	subnet := newSubnet(t, send)
	root := func(typ, iops, thru string) url.Values {
		f := url.Values{"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}}
		if typ != "" {
			f.Set("BlockDeviceMapping.1.Ebs.VolumeType", typ)
		}
		if iops != "" {
			f.Set("BlockDeviceMapping.1.Ebs.Iops", iops)
		}
		if thru != "" {
			f.Set("BlockDeviceMapping.1.Ebs.Throughput", thru)
		}
		return f
	}
	for _, c := range []struct {
		typ, iops, thru string
		wantIops        string
		wantThru        string
	}{
		{"gp3", "4000", "250", "4000", "250"},
		{"gp3", "", "750", "3000", "750"},
		{"io1", "400", "", "400", ""},
		{"io2", "8000", "", "8000", ""},
	} {
		name := c.typ + "/" + c.iops + "/" + c.thru
		run := send(launchForm(subnet, "perf-"+strings.ReplaceAll(name, "/", "-"), root(c.typ, c.iops, c.thru)))
		got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
		_, mapping, _ := strings.Cut(got, "<blockDeviceMapping>")
		vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {xmlText(t, mapping, "volumeId")}})
		if !strings.Contains(vols, "<volumeType>"+c.typ+"</volumeType>") {
			t.Errorf("%s: type lost: %s", name, vols)
		}
		if got := between(vols, "<iops>", "</iops>"); got != c.wantIops {
			t.Errorf("%s: iops %q, want %q", name, got, c.wantIops)
		}
		if got := between(vols, "<throughput>", "</throughput>"); got != c.wantThru {
			t.Errorf("%s: throughput %q, want %q", name, got, c.wantThru)
		}
	}
	for _, c := range []struct {
		name  string
		extra url.Values
		code  string
		msg   string
	}{
		{
			"gp2 iops", root("gp2", "3000", ""), "InvalidParameterCombination",
			"The parameter iops is not supported for gp2 volumes.",
		},
		{
			"default type iops", root("", "3000", ""), "InvalidParameterCombination",
			"The parameter iops is not supported for gp2 volumes.",
		},
		{
			"standard throughput", root("standard", "", "125"), "InvalidParameterCombination",
			"The parameter throughput is not supported for standard volumes.",
		},
		{
			"io1 throughput", root("io1", "100", "125"), "InvalidParameterCombination",
			"The parameter throughput is not supported for io1 volumes.",
		},
		{
			"io2 no iops", root("io2", "", ""), "MissingParameter",
			"The parameter iops must be specified for io2 volumes.",
		},
		{
			"io1 iops low", root("io1", "99", ""), "InvalidParameterValue",
			"Volume iops of 99 is too low; minimum is 100.",
		},
		{
			"io1 ratio", root("io1", "401", ""), "InvalidParameterValue",
			"Iops to volume size ratio of 50.125000 is too high; maximum is 50.000000",
		},
		{
			"io2 ratio", root("io2", "8001", ""), "InvalidParameterValue",
			"Iops to volume size ratio of 1000.125000 is too high; maximum is 1000.000000",
		},
		{
			"gp3 ratio", root("gp3", "4001", ""), "InvalidParameterValue",
			"Iops to volume size ratio of 500.125000 is too high; maximum is 500.000000",
		},
		{
			"gp3 iops low", root("gp3", "2999", ""), "InvalidParameterValue",
			"Volume iops of 2999 is too low; minimum is 3000.",
		},
		{
			"gp3 throughput high", root("gp3", "", "2001"), "InvalidParameterValue",
			"Volume throughput of 2001 is too high; maximum is 2000.",
		},
		{
			"gp3 throughput per iops", root("gp3", "", "751"), "InvalidParameterValue",
			"Throughput (MiBps) to iops ratio of 0.250333 is too high; maximum is 0.250000 MiBps per iops.",
		},
		{
			"iops not a number", root("gp3", "x", ""), "InvalidParameterValue",
			"Value (x) for parameter iops is invalid.",
		},
		{
			"throughput zero", root("gp3", "", "0"), "InvalidParameterValue",
			"Value (0) for parameter throughput is invalid.",
		},
	} {
		res := signed(t, h, cred, now, launchForm(subnet, "perf-refuse", c.extra).Encode())
		body := res.Body.String()
		if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+c.code+"</Code>") ||
			!strings.Contains(body, "<Message>"+c.msg+"</Message>") {
			t.Errorf("%s: want 400 %s %q, got %d %s", c.name, c.code, c.msg, res.Code, body)
		}
	}
	got := send(url.Values{"Action": {"DescribeInstances"}})
	if n := strings.Count(got, "<instanceId>"); n != 4 {
		t.Fatalf("%d instances after the refusals, want the 4 accepted launches", n)
	}
}
