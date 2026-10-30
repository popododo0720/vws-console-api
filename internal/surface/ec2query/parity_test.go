package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func parityForm(action string, pairs ...string) url.Values {
	form := url.Values{"Action": {action}, "Version": {Version}}
	for i := 0; i+1 < len(pairs); i += 2 {
		form.Set(pairs[i], pairs[i+1])
	}
	return form
}

func TestDescribeInstanceTypesListsTheMachineCatalog(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeInstanceTypes").Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", res.Code, res.Body)
	}
	for _, want := range []string{
		"<instanceType>vws.small</instanceType>", "<defaultVCpus>1</defaultVCpus>",
		"<memoryInfo><sizeInMiB>1024</sizeInMiB></memoryInfo>",
		"<instanceType>vws.xlarge</instanceType>", "<defaultVCpus>8</defaultVCpus>",
	} {
		if !strings.Contains(res.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, res.Body)
		}
	}

	arch := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
		"Filter.1.Name", "processor-info.supported-architecture", "Filter.1.Value.1", "x86_64").Encode())
	if arch.Code != http.StatusOK || !strings.Contains(arch.Body.String(), "<instanceType>vws.small</instanceType>") {
		t.Fatalf("architecture filter %d %s", arch.Code, arch.Body)
	}
	filtered := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
		"Filter.1.Name", "instance-type", "Filter.1.Value.1", "vws.medium").Encode())
	if filtered.Code != http.StatusOK ||
		!strings.Contains(filtered.Body.String(), "<instanceType>vws.medium</instanceType>") ||
		strings.Contains(filtered.Body.String(), "<instanceType>vws.small</instanceType>") {
		t.Fatalf("filter %d %s", filtered.Code, filtered.Body)
	}
	for _, pattern := range []string{"vws.*", "vws.?edium"} {
		wildcard := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
			"Filter.1.Name", "instance-type", "Filter.1.Value.1", pattern).Encode())
		if wildcard.Code != http.StatusOK ||
			!strings.Contains(wildcard.Body.String(), "<instanceType>vws.medium</instanceType>") {
			t.Fatalf("wildcard %s %d %s", pattern, wildcard.Code, wildcard.Body)
		}
	}
	unsupported := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
		"IncludeUnsupportedInRegion", "true").Encode())
	if unsupported.Code != http.StatusOK {
		t.Fatalf("include unsupported %d %s", unsupported.Code, unsupported.Body)
	}

	first := signed(t, h, cred, now, parityForm("DescribeInstanceTypes", "MaxResults", "2").Encode())
	if first.Code != http.StatusOK || strings.Count(first.Body.String(), "<instanceType>") != 2 {
		t.Fatalf("first page %d %s", first.Code, first.Body)
	}
	token := xmlText(t, first.Body.String(), "nextToken")
	second := signed(t, h, cred, now, parityForm("DescribeInstanceTypes", "MaxResults", "2", "NextToken", token).Encode())
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "<instanceType>vws.large</instanceType>") ||
		!strings.Contains(second.Body.String(), "<instanceType>vws.xlarge</instanceType>") {
		t.Fatalf("second page %d %s", second.Code, second.Body)
	}
	if strings.Contains(second.Body.String(), "<nextToken>") {
		t.Fatalf("last page has a token: %s", second.Body)
	}
}

func TestDescribeInstanceTypesAcceptsEveryDocumentedFilterName(t *testing.T) {
	h, cred, now := harness(t)
	for _, name := range []string{
		"dedicated-hosts-supported", "ebs-info.attachment-limit-type",
		"ebs-info.maximum-ebs-attachments", "network-info.bandwidth-weightings",
		"network-info.flexible-ena-queues-support", "reboot-migration-support",
		"vcpu-info.valid-cores", "vcpu-info.valid-threads-per-core",
	} {
		res := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
			"Filter.1.Name", name, "Filter.1.Value.1", "x").Encode())
		if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidParameterValue") {
			t.Fatalf("%s %d %s", name, res.Code, res.Body)
		}
	}
}

func TestDescribeInstanceStatusReportsRunningInstances(t *testing.T) {
	h, cred, now := harness(t)
	vpc := signed(t, h, cred, now, parityForm("CreateVpc", "CidrBlock", "10.30.0.0/16").Encode())
	subnet := signed(t, h, cred, now, parityForm("CreateSubnet",
		"VpcId", xmlText(t, vpc.Body.String(), "vpcId"), "CidrBlock", "10.30.1.0/24").Encode())
	run := signed(t, h, cred, now, parityForm("RunInstances",
		"ImageId", "ami-0123456789abcdef0", "InstanceType", "vws.small",
		"SubnetId", xmlText(t, subnet.Body.String(), "subnetId"), "MinCount", "1", "MaxCount", "1",
		"ClientToken", "status-run").Encode())
	if run.Code != http.StatusOK {
		t.Fatalf("run %d %s", run.Code, run.Body)
	}
	instanceID := xmlText(t, run.Body.String(), "instanceId")

	described := signed(t, h, cred, now, parityForm("DescribeInstanceStatus", "InstanceId.1", instanceID).Encode())
	if described.Code != http.StatusOK || strings.Contains(described.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", described.Code, described.Body)
	}
	for _, want := range []string{
		"<instanceStatusSet><item>", "<instanceId>" + instanceID + "</instanceId>",
		"<availabilityZone>vws-1a</availabilityZone>",
		"<instanceState><code>16</code><name>running</name></instanceState>",
		"<systemStatus><status>ok</status>" +
			"<details><item><name>reachability</name><status>passed</status></item></details></systemStatus>",
		"<instanceStatus><status>ok</status>",
	} {
		if !strings.Contains(described.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, described.Body)
		}
	}

	byStatus := signed(t, h, cred, now, parityForm("DescribeInstanceStatus",
		"Filter.1.Name", "instance-status.status", "Filter.1.Value.1", "ok").Encode())
	if byStatus.Code != http.StatusOK || !strings.Contains(byStatus.Body.String(), instanceID) {
		t.Fatalf("filter ok %d %s", byStatus.Code, byStatus.Body)
	}
	impaired := signed(t, h, cred, now, parityForm("DescribeInstanceStatus",
		"Filter.1.Name", "instance-status.status", "Filter.1.Value.1", "impaired").Encode())
	if impaired.Code != http.StatusOK || strings.Contains(impaired.Body.String(), instanceID) {
		t.Fatalf("filter impaired %d %s", impaired.Code, impaired.Body)
	}
	for _, tc := range []struct {
		name, value string
		row         bool
	}{
		{"availability-zone-id", "vws-1a", true},
		{"operator.managed", "false", true},
		{"operator.principal", "any", false},
		{"attached-ebs-status.status", "not-applicable", true},
		{"application-status.status", "not-applicable", true},
	} {
		res := signed(t, h, cred, now, parityForm("DescribeInstanceStatus",
			"Filter.1.Name", tc.name, "Filter.1.Value.1", tc.value).Encode())
		if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidParameterValue") {
			t.Fatalf("%s %d %s", tc.name, res.Code, res.Body)
		}
		if got := strings.Contains(res.Body.String(), instanceID); got != tc.row {
			t.Fatalf("%s row=%t body %s", tc.name, got, res.Body)
		}
	}
	for _, form := range []url.Values{
		parityForm("DescribeInstanceStatus", "IncludeManagedResources", "true"),
		parityForm("DescribeInstanceStatus", "includeManagedResources", "false"),
	} {
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidParameterValue") {
			t.Fatalf("include managed %d %s", res.Code, res.Body)
		}
	}
	missing := signed(t, h, cred, now, parityForm("DescribeInstanceStatus",
		"InstanceId.1", "i-00000000000000000").Encode())
	if missing.Code != http.StatusBadRequest ||
		!strings.Contains(missing.Body.String(), "InvalidInstanceID.NotFound") {
		t.Fatalf("missing instance %d %s", missing.Code, missing.Body)
	}

	stopped := signed(t, h, cred, now, parityForm("StopInstances", "InstanceId.1", instanceID).Encode())
	if stopped.Code != http.StatusOK {
		t.Fatalf("stop %d %s", stopped.Code, stopped.Body)
	}
	runningOnly := signed(t, h, cred, now, parityForm("DescribeInstanceStatus").Encode())
	if runningOnly.Code != http.StatusOK || strings.Contains(runningOnly.Body.String(), instanceID) {
		t.Fatalf("running only %d %s", runningOnly.Code, runningOnly.Body)
	}
	withStopped := signed(t, h, cred, now, parityForm("DescribeInstanceStatus",
		"includeAllInstances", "true").Encode())
	if withStopped.Code != http.StatusOK || !strings.Contains(withStopped.Body.String(), instanceID) ||
		!strings.Contains(withStopped.Body.String(), "<name>stopped</name>") {
		t.Fatalf("include all %d %s", withStopped.Code, withStopped.Body)
	}
}

func TestDescribeTagsListsTagsAcrossResourceTypes(t *testing.T) {
	h, cred, now := harness(t)
	vpc := signed(t, h, cred, now, parityForm("CreateVpc",
		"CidrBlock", "10.31.0.0/16",
		"TagSpecification.1.ResourceType", "vpc",
		"TagSpecification.1.Tag.1.Key", "env", "TagSpecification.1.Tag.1.Value", "dev").Encode())
	subnet := signed(t, h, cred, now, parityForm("CreateSubnet",
		"VpcId", xmlText(t, vpc.Body.String(), "vpcId"), "CidrBlock", "10.31.1.0/24",
		"TagSpecification.1.ResourceType", "subnet",
		"TagSpecification.1.Tag.1.Key", "tier", "TagSpecification.1.Tag.1.Value", "web").Encode())
	run := signed(t, h, cred, now, parityForm("RunInstances",
		"ImageId", "ami-0123456789abcdef0", "InstanceType", "vws.small",
		"SubnetId", xmlText(t, subnet.Body.String(), "subnetId"), "MinCount", "1", "MaxCount", "1",
		"ClientToken", "tags-run", "Tag.1.Key", "env", "Tag.1.Value", "dev").Encode())
	if run.Code != http.StatusOK {
		t.Fatalf("run %d %s", run.Code, run.Body)
	}
	instanceID := xmlText(t, run.Body.String(), "instanceId")
	subnetID := xmlText(t, subnet.Body.String(), "subnetId")
	vpcID := xmlText(t, vpc.Body.String(), "vpcId")

	described := signed(t, h, cred, now, parityForm("DescribeTags").Encode())
	if described.Code != http.StatusOK || strings.Contains(described.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", described.Code, described.Body)
	}
	for _, want := range []string{
		"<key>env</key><resourceId>" + instanceID + "</resourceId><resourceType>instance</resourceType><value>dev</value>",
		"<key>env</key><resourceId>" + vpcID + "</resourceId><resourceType>vpc</resourceType><value>dev</value>",
		"<key>tier</key><resourceId>" + subnetID + "</resourceId><resourceType>subnet</resourceType><value>web</value>",
	} {
		if !strings.Contains(described.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, described.Body)
		}
	}

	byType := signed(t, h, cred, now, parityForm("DescribeTags",
		"Filter.1.Name", "resource-type", "Filter.1.Value.1", "vpc").Encode())
	if byType.Code != http.StatusOK || !strings.Contains(byType.Body.String(), vpcID) ||
		strings.Contains(byType.Body.String(), instanceID) {
		t.Fatalf("resource-type %d %s", byType.Code, byType.Body)
	}
	byID := signed(t, h, cred, now, parityForm("DescribeTags",
		"Filter.1.Name", "resource-id", "Filter.1.Value.1", subnetID).Encode())
	if byID.Code != http.StatusOK || !strings.Contains(byID.Body.String(), "<key>tier</key>") ||
		strings.Contains(byID.Body.String(), "<key>env</key>") {
		t.Fatalf("resource-id %d %s", byID.Code, byID.Body)
	}
	byTag := signed(t, h, cred, now, parityForm("DescribeTags",
		"Filter.1.Name", "tag:env", "Filter.1.Value.1", "dev").Encode())
	if byTag.Code != http.StatusOK || strings.Contains(byTag.Body.String(), "InvalidParameterValue") ||
		!strings.Contains(byTag.Body.String(), instanceID) || !strings.Contains(byTag.Body.String(), vpcID) ||
		strings.Contains(byTag.Body.String(), subnetID) {
		t.Fatalf("tag:env %d %s", byTag.Code, byTag.Body)
	}

	first := signed(t, h, cred, now, parityForm("DescribeTags", "MaxResults", "1").Encode())
	if first.Code != http.StatusOK || strings.Count(first.Body.String(), "<item>") != 1 {
		t.Fatalf("first page %d %s", first.Code, first.Body)
	}
	token := xmlText(t, first.Body.String(), "nextToken")
	second := signed(t, h, cred, now, parityForm("DescribeTags", "MaxResults", "1", "NextToken", token).Encode())
	if second.Code != http.StatusOK || strings.Count(second.Body.String(), "<item>") != 1 ||
		second.Body.String() == first.Body.String() {
		t.Fatalf("second page %d %s", second.Code, second.Body)
	}
}

func TestDescribeVolumesModificationsIsAnEmptyPage(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeVolumesModifications").Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", res.Code, res.Body)
	}
	if !strings.Contains(res.Body.String(), "<volumeModificationSet></volumeModificationSet>") {
		t.Fatalf("shape %s", res.Body)
	}
	for _, form := range []url.Values{
		parityForm("DescribeVolumesModifications", "IncludeManagedResources", "true"),
		parityForm("DescribeVolumesModifications", "includeManagedResources", "false"),
	} {
		managed := signed(t, h, cred, now, form.Encode())
		if managed.Code != http.StatusOK || strings.Contains(managed.Body.String(), "InvalidParameterValue") {
			t.Fatalf("include managed %d %s", managed.Code, managed.Body)
		}
	}

	volume := signed(t, h, cred, now, parityForm("CreateVolume",
		"AvailabilityZone", resource.ZoneName, "Size", "8").Encode())
	id := xmlText(t, volume.Body.String(), "volumeId")
	known := signed(t, h, cred, now, parityForm("DescribeVolumesModifications", "VolumeId.1", id).Encode())
	if known.Code != http.StatusOK {
		t.Fatalf("known volume %d %s", known.Code, known.Body)
	}
	missing := signed(t, h, cred, now, parityForm("DescribeVolumesModifications",
		"VolumeId.1", "vol-00000000000000000").Encode())
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), "InvalidVolume.NotFound") {
		t.Fatalf("missing volume %d %s", missing.Code, missing.Body)
	}
}

func TestDescribeAvailabilityZonesReturnsTheZone(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeAvailabilityZones").Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", res.Code, res.Body)
	}
	for _, want := range []string{
		"<zoneName>vws-1a</zoneName>", "<zoneId>vws-1a</zoneId>", "<zoneState>available</zoneState>",
		"<regionName>vws-1</regionName>", "<optInStatus>opt-in-not-required</optInStatus>",
		"<groupLongName>VWS vws-1</groupLongName>",
	} {
		if !strings.Contains(res.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, res.Body)
		}
	}
	byGroup := signed(t, h, cred, now, parityForm("DescribeAvailabilityZones",
		"Filter.1.Name", "group-long-name", "Filter.1.Value.1", "VWS vws-1").Encode())
	if byGroup.Code != http.StatusOK || !strings.Contains(byGroup.Body.String(), "<zoneName>vws-1a</zoneName>") {
		t.Fatalf("group-long-name %d %s", byGroup.Code, byGroup.Body)
	}
	other := signed(t, h, cred, now, parityForm("DescribeAvailabilityZones", "ZoneName.1", "vws-9z").Encode())
	if other.Code != http.StatusOK || strings.Contains(other.Body.String(), "<zoneName>") {
		t.Fatalf("other zone %d %s", other.Code, other.Body)
	}
}

func TestDescribeRegionsReturnsTheRegion(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeRegions").Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", res.Code, res.Body)
	}
	for _, want := range []string{
		"<regionName>vws-1</regionName>", "<regionEndpoint>ec2.vws-1.vws.internal</regionEndpoint>",
		"<optInStatus>opt-in-not-required</optInStatus>",
	} {
		if !strings.Contains(res.Body.String(), want) {
			t.Fatalf("missing %s in %s", want, res.Body)
		}
	}
	other := signed(t, h, cred, now, parityForm("DescribeRegions", "RegionName.1", "vws-2").Encode())
	if other.Code != http.StatusOK || strings.Contains(other.Body.String(), "<regionName>") {
		t.Fatalf("other region %d %s", other.Code, other.Body)
	}
}

func TestDescribeRouteTablesIsAnEmptyPage(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeRouteTables").Encode())
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "InvalidAction") {
		t.Fatalf("describe %d %s", res.Code, res.Body)
	}
	if !strings.Contains(res.Body.String(), "<routeTableSet></routeTableSet>") {
		t.Fatalf("shape %s", res.Body)
	}
	byID := signed(t, h, cred, now, parityForm("DescribeRouteTables", "RouteTableId.1", "rtb-01234567").Encode())
	if byID.Code != http.StatusBadRequest ||
		!strings.Contains(byID.Body.String(), "InvalidRouteTableID.NotFound") {
		t.Fatalf("route table id %d %s", byID.Code, byID.Body)
	}
	malformed := signed(t, h, cred, now, parityForm("DescribeRouteTables", "RouteTableId.1", "rtb-nope").Encode())
	if malformed.Code != http.StatusBadRequest ||
		!strings.Contains(malformed.Body.String(), "InvalidRouteTableID.Malformed") {
		t.Fatalf("malformed route table id %d %s", malformed.Code, malformed.Body)
	}
	byTag := signed(t, h, cred, now, parityForm("DescribeRouteTables",
		"Filter.1.Name", "tag:env", "Filter.1.Value.1", "dev").Encode())
	if byTag.Code != http.StatusOK || strings.Contains(byTag.Body.String(), "InvalidParameterValue") {
		t.Fatalf("tag:env %d %s", byTag.Code, byTag.Body)
	}
}

func TestParityDescribesRejectUnknownFilters(t *testing.T) {
	h, cred, now := harness(t)
	for _, action := range []string{
		"DescribeInstanceStatus", "DescribeInstanceTypes", "DescribeTags",
		"DescribeVolumesModifications", "DescribeAvailabilityZones", "DescribeRegions", "DescribeRouteTables",
	} {
		res := signed(t, h, cred, now, parityForm(action,
			"Filter.1.Name", "not-a-filter", "Filter.1.Value.1", "x").Encode())
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidParameterValue") {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
	}
}
