package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func modifyVolumeForm(id, size string) string {
	form := url.Values{}
	form.Set("Action", "ModifyVolume")
	form.Set("Version", Version)
	form.Set("VolumeId", id)
	form.Set("Size", size)
	return form.Encode()
}

// #324 AC1: ModifyVolume Size follows the per-type ranges of the EC2 API
// Reference (ModifyVolume Size): standard 1-1024, gp2 1-16384, gp3 1-65536,
// io1 4-16384, io2 4-65536, st1 and sc1 125-16384 GiB. A size over the
// type's maximum is InvalidParameterValue and leaves the volume as it was.
func TestModifyVolumeEnforcesPerTypeSize(t *testing.T) {
	h, cred, now := harness(t)
	for _, tc := range []struct {
		create   map[string]string
		ok, over string
		max      string
	}{
		{map[string]string{"VolumeType": "standard", "Size": "10"}, "1024", "1025", "1024"},
		{map[string]string{"VolumeType": "gp2", "Size": "10"}, "16384", "16385", "16384"},
		{map[string]string{"VolumeType": "gp3", "Size": "10"}, "65536", "65537", "65536"},
		{map[string]string{"VolumeType": "io1", "Size": "10", "Iops": "500"}, "16384", "16385", "16384"},
		{map[string]string{"VolumeType": "io2", "Size": "10", "Iops": "10000"}, "65536", "65537", "65536"},
		{map[string]string{"VolumeType": "st1", "Size": "125"}, "16384", "16385", "16384"},
		{map[string]string{"VolumeType": "sc1", "Size": "125"}, "16384", "16385", "16384"},
	} {
		typ := tc.create["VolumeType"]
		res := signed(t, h, cred, now, createVolumeForm(tc.create))
		if res.Code != http.StatusOK {
			t.Fatalf("%s: create %d %s", typ, res.Code, res.Body)
		}
		id := between(res.Body.String(), "<volumeId>", "</volumeId>")

		res = signed(t, h, cred, now, modifyVolumeForm(id, tc.over))
		want := "Volume of " + tc.over + "GiB is too large; maximum is " + tc.max + "GiB."
		body := res.Body.String()
		if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidParameterValue</Code>") ||
			!strings.Contains(body, "<Message>"+want+"</Message>") {
			t.Errorf("%s grow to %s: want 400 InvalidParameterValue %q, got %d %s", typ, tc.over, want, res.Code, body)
		}

		res = signed(t, h, cred, now, modifyVolumeForm(id, tc.ok))
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<targetSize>"+tc.ok+"</targetSize>") {
			t.Errorf("%s grow to %s: want 200 targetSize %s, got %d %s", typ, tc.ok, tc.ok, res.Code, res.Body)
		}
	}
}

func modifyForm(id string, params map[string]string) string {
	form := url.Values{}
	form.Set("Action", "ModifyVolume")
	form.Set("Version", Version)
	form.Set("VolumeId", id)
	for k, v := range params {
		form.Set(k, v)
	}
	return form.Encode()
}

// #324 AC1: ModifyVolume takes VolumeType, Iops and Throughput with Size in
// one call and answers the target and original values in volumeModification
// (EC2 API Reference, ModifyVolume and VolumeModification). Values the target
// type cannot hold are refused with EC2's codes and change nothing. A retry
// with the same ClientToken answers the first modification's target; its
// original values are re-read, which #617 tracks.
func TestModifyVolumeTakesTypeIopsAndThroughput(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, createVolumeForm(map[string]string{"VolumeType": "gp2", "Size": "10"}))
	if res.Code != http.StatusOK {
		t.Fatalf("create: %d %s", res.Code, res.Body)
	}
	id := between(res.Body.String(), "<volumeId>", "</volumeId>")
	for _, tc := range []struct {
		params map[string]string
		code   string
	}{
		{map[string]string{"VolumeType": "st1"}, "InvalidParameterValue"},
		{map[string]string{"VolumeType": "io1"}, "InvalidParameterValue"},
		{map[string]string{"Iops": "3000"}, "InvalidParameterCombination"},
		{map[string]string{"VolumeType": "io2", "Throughput": "500"}, "InvalidParameterCombination"},
		{map[string]string{"VolumeType": "gp4"}, "UnknownVolumeType"},
		{map[string]string{"Iops": "0"}, "InvalidParameterValue"},
		{map[string]string{"Throughput": "x"}, "InvalidParameterValue"},
		{map[string]string{"Size": "-1"}, "InvalidParameterValue"},
		{map[string]string{}, "MissingParameter"},
		{map[string]string{"MultiAttachEnabled": "true"}, ""},
	} {
		res := signed(t, h, cred, now, modifyForm(id, tc.params))
		if res.Code != http.StatusBadRequest ||
			(tc.code != "" && !strings.Contains(res.Body.String(), "<Code>"+tc.code+"</Code>")) {
			t.Errorf("%v: want 400 %s, got %d %s", tc.params, tc.code, res.Code, res.Body)
		}
	}

	retype := map[string]string{
		"VolumeType":  "gp3",
		"Size":        "100",
		"Iops":        "6000",
		"Throughput":  "500",
		"ClientToken": "retype-324",
	}
	first := signed(t, h, cred, now, modifyForm(id, retype))
	body := first.Body.String()
	for _, want := range []string{
		"<targetSize>100</targetSize>", "<originalSize>10</originalSize>",
		"<targetVolumeType>gp3</targetVolumeType>", "<originalVolumeType>gp2</originalVolumeType>",
		"<targetIops>6000</targetIops>", "<originalIops>100</originalIops>",
		"<targetThroughput>500</targetThroughput>",
	} {
		if first.Code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("gp2 to gp3: want 200 with %s, got %d %s", want, first.Code, body)
		}
	}
	if strings.Contains(body, "<originalThroughput>") {
		t.Errorf("gp2 has no throughput to report: %s", body)
	}
	again := signed(t, h, cred, now, modifyForm(id, retype))
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), "<targetIops>6000</targetIops>") {
		t.Errorf("retry with the same ClientToken: %d %s", again.Code, again.Body)
	}

	described := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeVolumes"}, "Version": {Version}, "VolumeId.1": {id},
	}.Encode())
	for _, want := range []string{
		"<volumeType>gp3</volumeType>", "<size>100</size>", "<iops>6000</iops>", "<throughput>500</throughput>",
	} {
		if !strings.Contains(described.Body.String(), want) {
			t.Errorf("describe after modify: want %s, got %s", want, described.Body)
		}
	}
}
