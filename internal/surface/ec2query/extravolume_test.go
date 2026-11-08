package ec2query

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// mappedBlock is one blockDeviceMapping item of DescribeInstances.
type mappedBlock struct{ device, volumeID, deleteOnTermination string }

// mappedBlocks reads the blockDeviceMapping items of the one instance in
// body, in order.
func mappedBlocks(t *testing.T, body string) []mappedBlock {
	t.Helper()
	_, rest, ok := strings.Cut(body, "<blockDeviceMapping>")
	if !ok {
		t.Fatalf("no blockDeviceMapping in %s", body)
	}
	rest, _, _ = strings.Cut(rest, "</blockDeviceMapping>")
	var out []mappedBlock
	for _, item := range strings.Split(rest, "<deviceName>")[1:] {
		item = "<deviceName>" + item
		out = append(out, mappedBlock{
			device: xmlText(t, item, "deviceName"), volumeID: xmlText(t, item, "volumeId"),
			deleteOnTermination: xmlText(t, item, "deleteOnTermination"),
		})
	}
	return out
}

// mappings is n extra mappings of 1 GiB at /dev/xvdaa onward, from index
// first.
func mappings(first, n int) url.Values {
	f := url.Values{}
	for i := range n {
		prefix := "BlockDeviceMapping." + strconv.Itoa(first+i) + "."
		f.Set(prefix+"DeviceName", "/dev/xvd"+string(rune('a'+i/26))+string(rune('a'+i%26)))
		f.Set(prefix+"Ebs.VolumeSize", "1")
	}
	return f
}

// #423 AC2 and AC3: each mapping for a device other than the root adds a
// volume of its size, type and performance to the instance at that device,
// and its Ebs.DeleteOnTermination, true when omitted, reads back on
// DescribeInstances and DescribeVolumes. Once the instance terminates, a
// volume deleted with it is gone and a kept one is available. The mappings
// are part of the request, so a retry with the same ClientToken returns the
// instance and one with another mapping is IdempotentParameterMismatch.
func TestRunInstancesExtraVolumesRoundTrip(t *testing.T) {
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
	form := launchForm(subnet, "extra", url.Values{
		"BlockDeviceMapping.1.DeviceName": {"/dev/sdf"}, "BlockDeviceMapping.1.Ebs.VolumeSize": {"20"},
		"BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"}, "BlockDeviceMapping.1.Ebs.Throughput": {"250"},
		"BlockDeviceMapping.2.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.2.Ebs.VolumeType": {"gp3"},
		"BlockDeviceMapping.4.DeviceName": {"/dev/sdg"}, "BlockDeviceMapping.4.Ebs.VolumeSize": {"125"},
		"BlockDeviceMapping.4.Ebs.VolumeType": {"st1"}, "BlockDeviceMapping.4.Ebs.DeleteOnTermination": {"FALSE"},
		"BlockDeviceMapping.5.DeviceName": {"xvdh"}, "BlockDeviceMapping.5.Ebs.VolumeSize": {"10"},
		"BlockDeviceMapping.5.Ebs.VolumeType": {"io1"}, "BlockDeviceMapping.5.Ebs.Iops": {"500"},
		"BlockDeviceMapping.5.Ebs.DeleteOnTermination": {"true"}, "BlockDeviceMapping.5.Ebs.Encrypted": {"false"},
	})
	inst := xmlText(t, send(form), "instanceId")
	blocks := mappedBlocks(t, send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {inst}}))
	want := []struct{ device, dot, volume string }{
		{"/dev/xvda", "true", "<volumeType>gp3</volumeType>"},
		{"/dev/sdf", "true", "<throughput>250</throughput>"},
		{"/dev/sdg", "false", "<volumeType>st1</volumeType>"},
		{"xvdh", "true", "<iops>500</iops>"},
	}
	if len(blocks) != len(want) {
		t.Fatalf("block devices %+v", blocks)
	}
	for i, w := range want {
		b := blocks[i]
		if b.device != w.device || b.deleteOnTermination != w.dot {
			t.Fatalf("block device %d %+v, want %s deleteOnTermination %s", i, b, w.device, w.dot)
		}
		vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {b.volumeID}})
		for _, part := range []string{
			w.volume, "<status>in-use</status>", "<instanceId>" + inst + "</instanceId>",
			"<device>" + w.device + "</device>", "<deleteOnTermination>" + w.dot + "</deleteOnTermination>",
		} {
			if !strings.Contains(vols, part) {
				t.Fatalf("volume at %s lacks %s: %s", w.device, part, vols)
			}
		}
	}
	if again := xmlText(t, send(form), "instanceId"); again != inst {
		t.Fatalf("replay launched %s, want %s", again, inst)
	}
	changed := launchForm(subnet, "extra", nil)
	for k, v := range form {
		changed[k] = v
	}
	changed.Set("BlockDeviceMapping.1.Ebs.VolumeSize", "21")
	res := signed(t, h, cred, now, changed.Encode())
	if res.Code != http.StatusBadRequest ||
		!strings.Contains(res.Body.String(), "<Code>IdempotentParameterMismatch</Code>") {
		t.Fatalf("another size under the same token: %d %s", res.Code, res.Body)
	}
	send(url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {inst}})
	send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {inst}})
	all := send(url.Values{"Action": {"DescribeVolumes"}})
	for _, b := range blocks {
		listed := strings.Contains(all, "<volumeId>"+b.volumeID+"</volumeId>")
		if listed != (b.deleteOnTermination == "false") {
			t.Fatalf("after terminate, %s listed %v: %s", b.device, listed, all)
		}
	}
	kept := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {blocks[2].volumeID}})
	if !strings.Contains(kept, "<status>available</status>") || strings.Contains(kept, "<instanceId>") {
		t.Fatalf("kept extra volume after terminate %s", kept)
	}
}

// #423 AC2: an instance takes 26 extra volumes beside its root, the EBS
// limit of a Nitro instance with one network interface.
func TestRunInstancesTakesTheMostExtraVolumes(t *testing.T) {
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
	inst := xmlText(t, send(launchForm(subnet, "most", mappings(1, 26))), "instanceId")
	if got := mappedBlocks(t, send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {inst}})); len(got) != 27 {
		t.Fatalf("block devices %d, want 27", len(got))
	}
}

// #423 AC2: an extra mapping VWS or EC2 would not take is refused before
// anything is created, with the EC2 code for the reason.
func TestRunInstancesExtraVolumeRefusals(t *testing.T) {
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
	extra := func(fields ...string) url.Values {
		f := url.Values{"BlockDeviceMapping.1.DeviceName": {"/dev/sdf"}}
		for i := 0; i+1 < len(fields); i += 2 {
			f.Set("BlockDeviceMapping.1."+fields[i], fields[i+1])
		}
		return f
	}
	twice := func(first, second string) url.Values {
		return url.Values{
			"BlockDeviceMapping.1.DeviceName": {first}, "BlockDeviceMapping.1.Ebs.VolumeSize": {"8"},
			"BlockDeviceMapping.2.DeviceName": {second}, "BlockDeviceMapping.2.Ebs.VolumeSize": {"8"},
		}
	}
	for _, c := range []struct {
		name, code, message string
		extra               url.Values
	}{
		{
			name: "27 extra volumes", code: "AttachmentLimitExceeded",
			message: "a VWS instance takes 27, the root volume included",
			extra:   mappings(1, 27),
		},
		{
			name: "no size", code: "InvalidBlockDeviceMapping",
			message: "/dev/sdf: you must specify either a snapshot ID or a volume size",
			extra:   extra("Ebs.VolumeType", "gp3"),
		},
		{
			name: "zero size", code: "InvalidParameterValue",
			message: "Value (0) for parameter size is invalid.",
			extra:   extra("Ebs.VolumeSize", "0"),
		},
		{
			name: "not an EBS device", code: "InvalidBlockDeviceMapping",
			message: "/dev/foo is not a valid EBS device name.",
			extra:   url.Values{"BlockDeviceMapping.1.DeviceName": {"/dev/foo"}, "BlockDeviceMapping.1.Ebs.VolumeSize": {"8"}},
		},
		{
			name: "one device twice", code: "InvalidBlockDeviceMapping",
			message: "device /dev/sdf is mapped more than once",
			extra:   twice("/dev/sdf", "/dev/sdf"),
		},
		{
			name: "one xvd device with and without /dev/", code: "InvalidBlockDeviceMapping",
			message: "device xvdf is mapped more than once",
			extra:   twice("/dev/xvdf", "xvdf"),
		},
		{
			name: "the root device without /dev/", code: "InvalidBlockDeviceMapping",
			message: "device xvda is mapped more than once",
			extra:   twice("/dev/sdf", "xvda"),
		},
		{
			name: "st1 below 125 GiB", code: "InvalidParameterValue",
			message: "Volume of 124GiB is too small; minimum is 125GiB.",
			extra:   extra("Ebs.VolumeSize", "124", "Ebs.VolumeType", "st1"),
		},
		{
			name: "unknown type", code: "UnknownVolumeType",
			message: "unsupported",
			extra:   extra("Ebs.VolumeSize", "8", "Ebs.VolumeType", "io3"),
		},
		{
			name: "io1 without iops", code: "MissingParameter",
			message: "The parameter iops must be specified for io1 volumes.",
			extra:   extra("Ebs.VolumeSize", "8", "Ebs.VolumeType", "io1"),
		},
		{
			name: "gp2 throughput", code: "InvalidParameterCombination",
			message: "The parameter throughput is not supported for gp2 volumes.",
			extra:   extra("Ebs.VolumeSize", "8", "Ebs.Throughput", "200"),
		},
		{
			name: "encrypted", code: "UnsupportedOperation",
			message: "BlockDeviceMapping.1.Ebs.Encrypted is not supported: ",
			extra:   extra("Ebs.VolumeSize", "8", "Ebs.Encrypted", "true"),
		},
		{
			name: "from a snapshot", code: "UnsupportedOperation",
			message: "BlockDeviceMapping.1.Ebs.SnapshotId is not supported: " +
				"VWS creates the root volume from the image and every other launch volume blank.",
			extra: extra("Ebs.SnapshotId", "snap-0123456789abcdef0"),
		},
		{
			name: "an unread field", code: "InvalidParameterValue",
			message: "",
			extra:   extra("Ebs.VolumeSize", "8", "Ebs.OutpostArn", "arn"),
		},
	} {
		res := signed(t, h, cred, now, launchForm(subnet, "extra-refuse", c.extra).Encode())
		body := res.Body.String()
		if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+c.code+"</Code>") ||
			!strings.Contains(body, c.message) {
			t.Fatalf("%s: %d %s", c.name, res.Code, body)
		}
	}
	if got := send(url.Values{"Action": {"DescribeInstances"}}); strings.Contains(got, "<instanceId>") {
		t.Fatalf("a refused launch created an instance: %s", got)
	}
	if got := send(url.Values{"Action": {"DescribeVolumes"}}); strings.Contains(got, "<volumeId>") {
		t.Fatalf("a refused launch created a volume: %s", got)
	}
}
