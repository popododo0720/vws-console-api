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
