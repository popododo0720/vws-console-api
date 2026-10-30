package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func createVolumeForm(params map[string]string) string {
	form := url.Values{}
	form.Set("Action", "CreateVolume")
	form.Set("Version", Version)
	form.Set("AvailabilityZone", "vws-1a")
	for k, v := range params {
		form.Set(k, v)
	}
	return form.Encode()
}

// #324 AC1: CreateVolume takes all seven EBS types with the per-type rules of
// the EC2 API Reference (CreateVolume Size, Iops and Throughput) and the EBS
// volume types page, and refuses the rest with EC2's codes:
// InvalidParameterCombination for a parameter the type does not take,
// MissingParameter for io1/io2 without Iops, InvalidParameterValue for a
// value out of range or over a ratio.
func TestCreateVolumeEnforcesPerTypeRules(t *testing.T) {
	h, cred, now := harness(t)
	for _, tc := range []struct {
		name   string
		params map[string]string
		code   string
		msg    string
	}{
		{"standard max", map[string]string{"VolumeType": "standard", "Size": "1025"},
			"InvalidParameterValue", "Volume of 1025GiB is too large; maximum is 1024GiB."},
		{"gp2 max", map[string]string{"VolumeType": "gp2", "Size": "16385"},
			"InvalidParameterValue", "Volume of 16385GiB is too large; maximum is 16384GiB."},
		{"gp3 max", map[string]string{"VolumeType": "gp3", "Size": "65537"},
			"InvalidParameterValue", "Volume of 65537GiB is too large; maximum is 65536GiB."},
		{"io1 min", map[string]string{"VolumeType": "io1", "Size": "3", "Iops": "100"},
			"InvalidParameterValue", "Volume of 3GiB is too small; minimum is 4GiB."},
		{"io2 max", map[string]string{"VolumeType": "io2", "Size": "65537", "Iops": "100"},
			"InvalidParameterValue", "Volume of 65537GiB is too large; maximum is 65536GiB."},
		{"st1 min", map[string]string{"VolumeType": "st1", "Size": "124"},
			"InvalidParameterValue", "Volume of 124GiB is too small; minimum is 125GiB."},
		{"sc1 max", map[string]string{"VolumeType": "sc1", "Size": "16385"},
			"InvalidParameterValue", "Volume of 16385GiB is too large; maximum is 16384GiB."},
		{"size zero", map[string]string{"Size": "0"},
			"InvalidParameterValue", "Value (0) for parameter size is invalid."},
		{"gp2 iops", map[string]string{"VolumeType": "gp2", "Size": "10", "Iops": "3000"},
			"InvalidParameterCombination", "The parameter iops is not supported for gp2 volumes."},
		{"st1 iops", map[string]string{"VolumeType": "st1", "Size": "125", "Iops": "500"},
			"InvalidParameterCombination", "The parameter iops is not supported for st1 volumes."},
		{"io1 throughput", map[string]string{"VolumeType": "io1", "Size": "10", "Iops": "100", "Throughput": "125"},
			"InvalidParameterCombination", "The parameter throughput is not supported for io1 volumes."},
		{"standard throughput", map[string]string{"VolumeType": "standard", "Size": "10", "Throughput": "125"},
			"InvalidParameterCombination", "The parameter throughput is not supported for standard volumes."},
		{"io1 no iops", map[string]string{"VolumeType": "io1", "Size": "10"},
			"MissingParameter", "The parameter iops must be specified for io1 volumes."},
		{"io2 no iops", map[string]string{"VolumeType": "io2", "Size": "10"},
			"MissingParameter", "The parameter iops must be specified for io2 volumes."},
		{"gp3 iops low", map[string]string{"VolumeType": "gp3", "Size": "100", "Iops": "2999"},
			"InvalidParameterValue", "Volume iops of 2999 is too low; minimum is 3000."},
		{"gp3 iops high", map[string]string{"VolumeType": "gp3", "Size": "1000", "Iops": "80001"},
			"InvalidParameterValue", "Volume iops of 80001 is too high; maximum is 80000."},
		{"io1 iops low", map[string]string{"VolumeType": "io1", "Size": "10", "Iops": "99"},
			"InvalidParameterValue", "Volume iops of 99 is too low; minimum is 100."},
		{"io1 iops high", map[string]string{"VolumeType": "io1", "Size": "16384", "Iops": "64001"},
			"InvalidParameterValue", "Volume iops of 64001 is too high; maximum is 64000."},
		{"io2 iops high", map[string]string{"VolumeType": "io2", "Size": "65536", "Iops": "256001"},
			"InvalidParameterValue", "Volume iops of 256001 is too high; maximum is 256000."},
		{"gp3 throughput low", map[string]string{"VolumeType": "gp3", "Size": "10", "Throughput": "124"},
			"InvalidParameterValue", "Volume throughput of 124 is too low; minimum is 125."},
		{"gp3 throughput high", map[string]string{"VolumeType": "gp3", "Size": "1000", "Iops": "16000", "Throughput": "2001"},
			"InvalidParameterValue", "Volume throughput of 2001 is too high; maximum is 2000."},
		{"io1 ratio", map[string]string{"VolumeType": "io1", "Size": "10", "Iops": "501"},
			"InvalidParameterValue", "Iops to volume size ratio of 50.100000 is too high; maximum is 50.000000"},
		{"io2 ratio", map[string]string{"VolumeType": "io2", "Size": "10", "Iops": "10001"},
			"InvalidParameterValue", "Iops to volume size ratio of 1000.100000 is too high; maximum is 1000.000000"},
		{"gp3 ratio", map[string]string{"VolumeType": "gp3", "Size": "10", "Iops": "5001"},
			"InvalidParameterValue", "Iops to volume size ratio of 500.100000 is too high; maximum is 500.000000"},
		{"gp3 throughput per iops", map[string]string{"VolumeType": "gp3", "Size": "10", "Throughput": "751"},
			"InvalidParameterValue",
			"Throughput (MiBps) to iops ratio of 0.250333 is too high; maximum is 0.250000 MiBps per iops."},
		{"iops not a number", map[string]string{"VolumeType": "gp3", "Size": "10", "Iops": "x"},
			"InvalidParameterValue", "Value (x) for parameter iops is invalid."},
		{"throughput zero", map[string]string{"VolumeType": "gp3", "Size": "10", "Throughput": "0"},
			"InvalidParameterValue", "Value (0) for parameter throughput is invalid."},
	} {
		res := signed(t, h, cred, now, createVolumeForm(tc.params))
		body := res.Body.String()
		if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+tc.code+"</Code>") ||
			!strings.Contains(body, "<Message>"+tc.msg+"</Message>") {
			t.Errorf("%s: want 400 %s %q, got %d %s", tc.name, tc.code, tc.msg, res.Code, body)
		}
	}
	desc := url.Values{}
	desc.Set("Action", "DescribeVolumes")
	desc.Set("Version", Version)
	res := signed(t, h, cred, now, desc.Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "<volumeId>") {
		t.Fatalf("a refused CreateVolume left a volume: %d %s", res.Code, res.Body)
	}
}

// #324 AC1 and AC2: each type at its edges is accepted, and the Iops and
// Throughput a volume has come back from CreateVolume and DescribeVolumes as
// EC2 returns them: provisioned for gp3/io1/io2 (gp3 defaults 3000 and 125),
// the 3 IOPS per GiB baseline (100 to 16000) for gp2, none for the others.
func TestCreateVolumeStoresAndReturnsIopsAndThroughput(t *testing.T) {
	h, cred, now := harness(t)
	for _, tc := range []struct {
		params     map[string]string
		iops, thru string
	}{
		{map[string]string{"VolumeType": "standard", "Size": "1024"}, "", ""},
		{map[string]string{"VolumeType": "gp2", "Size": "1"}, "100", ""},
		{map[string]string{"VolumeType": "gp2", "Size": "500"}, "1500", ""},
		{map[string]string{"VolumeType": "gp2", "Size": "16384"}, "16000", ""},
		{map[string]string{"VolumeType": "gp3", "Size": "1"}, "3000", "125"},
		{map[string]string{"VolumeType": "gp3", "Size": "65536", "Iops": "80000", "Throughput": "2000"}, "80000", "2000"},
		{map[string]string{"VolumeType": "gp3", "Size": "10", "Throughput": "750"}, "3000", "750"},
		{map[string]string{"VolumeType": "io1", "Size": "4", "Iops": "200"}, "200", ""},
		{map[string]string{"VolumeType": "io1", "Size": "16384", "Iops": "64000"}, "64000", ""},
		{map[string]string{"VolumeType": "io2", "Size": "4", "Iops": "4000"}, "4000", ""},
		{map[string]string{"VolumeType": "io2", "Size": "65536", "Iops": "256000"}, "256000", ""},
		{map[string]string{"VolumeType": "st1", "Size": "125"}, "", ""},
		{map[string]string{"VolumeType": "sc1", "Size": "16384"}, "", ""},
	} {
		name := tc.params["VolumeType"] + "/" + tc.params["Size"]
		res := signed(t, h, cred, now, createVolumeForm(tc.params))
		if res.Code != http.StatusOK {
			t.Fatalf("%s: create %d %s", name, res.Code, res.Body)
		}
		created := res.Body.String()
		desc := url.Values{}
		desc.Set("Action", "DescribeVolumes")
		desc.Set("Version", Version)
		desc.Set("VolumeId.1", between(created, "<volumeId>", "</volumeId>"))
		res = signed(t, h, cred, now, desc.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s: describe %d %s", name, res.Code, res.Body)
		}
		for step, body := range map[string]string{"create": created, "describe": res.Body.String()} {
			if got := between(body, "<iops>", "</iops>"); got != tc.iops {
				t.Errorf("%s %s: iops %q, want %q", name, step, got, tc.iops)
			}
			if got := between(body, "<throughput>", "</throughput>"); got != tc.thru {
				t.Errorf("%s %s: throughput %q, want %q", name, step, got, tc.thru)
			}
			if !strings.Contains(body, "<volumeType>"+tc.params["VolumeType"]+"</volumeType>") {
				t.Errorf("%s %s: type lost: %s", name, step, body)
			}
		}
	}
}
