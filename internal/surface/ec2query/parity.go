package ec2query

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// zoneID is the stable id of resource.ZoneName. VWS has one zone and no
// separate zone id space.
const zoneID = "vws-1a"

// queryFilter is one EC2 Filter.N. Every value in one filter is ORed, and
// every filter is ANDed with the rest.
type queryFilter struct {
	name   string
	values []string
}

func queryFilters(r *http.Request) ([]queryFilter, error) {
	var out []queryFilter
	for i := 1; i <= 20; i++ {
		name := r.Form.Get("Filter." + strconv.Itoa(i) + ".Name")
		values := indexedStrings(r, "Filter."+strconv.Itoa(i)+".Value")
		if name == "" {
			if len(values) > 0 {
				return nil, resource.Invalid("Filter", "malformed")
			}
			continue
		}
		out = append(out, queryFilter{name: name, values: values})
	}
	return out, nil
}

func checkFilterNames(filters []queryFilter, allowed ...string) error {
	return checkFilterNameList(filters, false, allowed)
}

// checkTagFilterNames is checkFilterNames plus EC2's tag:<key> form.
func checkTagFilterNames(filters []queryFilter, allowed ...string) error {
	return checkFilterNameList(filters, true, allowed)
}

func checkFilterNameList(filters []queryFilter, allowTag bool, allowed []string) error {
	names := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		names[name] = struct{}{}
	}
	for _, f := range filters {
		if _, ok := names[f.name]; ok {
			continue
		}
		if allowTag {
			if key, ok := strings.CutPrefix(f.name, "tag:"); ok && key != "" {
				continue
			}
		}
		return resource.Invalid("Filter", "unsupported")
	}
	return nil
}

func filtersMatch(filters []queryFilter, values func(string) []string) bool {
	for _, f := range filters {
		matched := false
		for _, want := range f.values {
			for _, got := range values(f.name) {
				if wildcardMatch(want, got) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// wildcardMatch applies EC2's * and ? filter wildcards. A pattern without
// either character is an exact match.
func wildcardMatch(pattern, value string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	p, v := []rune(pattern), []rune(value)
	pi, vi := 0, 0
	star, mark := -1, 0
	for vi < len(v) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == v[vi]):
			pi++
			vi++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, vi
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			vi = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// pageRows slices rows after filtering them in the codec. The token is the
// identity of the last row on the previous page, the same cursor the backends
// use.
func pageRows[T any](rows []T, page resource.PageRequest, identity func(T) string) ([]T, string, error) {
	page, err := page.Normalize()
	if err != nil {
		return nil, "", err
	}
	start := 0
	if page.Token != "" {
		found := false
		for i, row := range rows {
			if identity(row) == page.Token {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, "", resource.Invalid("NextToken", "unknown")
		}
	}
	end := min(start+page.Size, len(rows))
	next := ""
	if end < len(rows) {
		next = identity(rows[end-1])
	}
	return rows[start:end], next, nil
}

// collectPages reads every page of one listing so the codec can apply filters
// over the whole result before it pages it again.
func collectPages[Q resource.Query[Q], T resource.Owned](
	ctx context.Context,
	c resource.Caller,
	query func(resource.PageRequest) Q,
	call func(context.Context, resource.Caller, Q) (resource.Page[T], error),
) ([]T, error) {
	var out []T
	token := ""
	for {
		page, err := call(ctx, c, query(resource.PageRequest{Size: 100, Token: token}))
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.NextToken == "" {
			return out, nil
		}
		if page.NextToken == token {
			return nil, resource.Internal(errors.New("page token did not advance"))
		}
		token = page.NextToken
	}
}

func (h *handler) allInstances(ctx context.Context, c resource.Caller) ([]resource.Instance, error) {
	return collectPages(ctx, c, func(page resource.PageRequest) resource.InstanceQuery {
		return resource.InstanceQuery{Page: page}
	}, h.svc.DescribeInstances)
}

func (h *handler) allVpcs(ctx context.Context, c resource.Caller) ([]resource.Vpc, error) {
	return collectPages(ctx, c, func(page resource.PageRequest) resource.VpcQuery {
		return resource.VpcQuery{Page: page}
	}, h.svc.DescribeVpcs)
}

func (h *handler) allSubnets(ctx context.Context, c resource.Caller) ([]resource.Subnet, error) {
	return collectPages(ctx, c, func(page resource.PageRequest) resource.SubnetQuery {
		return resource.SubnetQuery{Page: page}
	}, h.svc.DescribeSubnets)
}

func (h *handler) describeInstanceStatus(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkFilterNames(filters,
		"application-status.status", "attached-ebs-status.status",
		"availability-zone", "availability-zone-id", "event.code", "event.description",
		"event.instance-event-id", "event.not-after", "event.not-before",
		"event.not-before-deadline", "instance-id", "instance-state-code",
		"instance-state-name", "instance-status.reachability", "instance-status.status",
		"operator.managed", "operator.principal", "system-status.reachability",
		"system-status.status",
	); err != nil {
		writeErr(w, r, err)
		return
	}
	includeAll, err := boolForm(r, "IncludeAllInstances")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := boolForm(r, "IncludeManagedResources"); err != nil {
		writeErr(w, r, err)
		return
	}
	if len(ids) > 0 && (r.Form.Get("MaxResults") != "" || r.Form.Get("maxResults") != "") {
		writeErr(w, r, resource.InvalidCombination("MaxResults", "cannot be used with InstanceId"))
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	instances, err := h.allInstances(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	want := make(map[resource.InstanceID]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	exists := make(map[resource.InstanceID]struct{}, len(instances))
	for _, inst := range instances {
		exists[inst.ID] = struct{}{}
	}
	for id := range want {
		if _, ok := exists[id]; !ok {
			writeErr(w, r, resource.NotFound(resource.KindInstance, id.String()))
			return
		}
	}
	var rows []instanceStatusItem
	for _, inst := range instances {
		if !includeAll && inst.State != resource.InstanceRunning {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[inst.ID]; !ok {
				continue
			}
		}
		row := instanceStatusOf(inst)
		if !filtersMatch(filters, row.filterValue) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].InstanceID < rows[j].InstanceID })
	rows, next, err := pageRows(rows, page, func(row instanceStatusItem) string { return row.InstanceID })
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, describeInstanceStatusXML{
		InstanceStatuses: instanceStatusSetXML{Items: rows}, NextToken: next, RequestID: requestID(r),
	})
}

func instanceStatusOf(inst resource.Instance) instanceStatusItem {
	return instanceStatusItem{
		InstanceID:       inst.ID.String(),
		AvailabilityZone: inst.Zone,
		State:            stateXMLOf(inst.State),
		SystemStatus:     statusCheckXMLOf(inst.State),
		InstanceStatus:   statusCheckXMLOf(inst.State),
	}
}

func statusCheckXMLOf(state resource.InstanceState) statusCheckXML {
	if state == resource.InstanceRunning {
		return statusCheckXML{Status: "ok", Details: []statusDetailXML{{Name: "reachability", Status: "passed"}}}
	}
	return statusCheckXML{
		Status:  "not-applicable",
		Details: []statusDetailXML{{Name: "reachability", Status: "not-applicable"}},
	}
}

func (s statusCheckXML) reachability() string {
	if len(s.Details) == 0 {
		return ""
	}
	return s.Details[0].Status
}

func (i instanceStatusItem) filterValue(name string) []string {
	switch name {
	case "application-status.status", "attached-ebs-status.status":
		return []string{"not-applicable"}
	case "availability-zone":
		return []string{i.AvailabilityZone}
	case "availability-zone-id":
		return []string{zoneID}
	case "instance-id":
		return []string{i.InstanceID}
	case "instance-state-code":
		return []string{strconv.Itoa(i.State.Code)}
	case "instance-state-name":
		return []string{i.State.Name}
	case "instance-status.reachability":
		return []string{i.InstanceStatus.reachability()}
	case "instance-status.status":
		return []string{i.InstanceStatus.Status}
	case "operator.managed":
		return []string{"false"}
	case "operator.principal":
		return nil
	case "system-status.reachability":
		return []string{i.SystemStatus.reachability()}
	case "system-status.status":
		return []string{i.SystemStatus.Status}
	case "event.code", "event.description", "event.instance-event-id",
		"event.not-after", "event.not-before", "event.not-before-deadline":
		return nil
	default:
		return nil
	}
}

func (h *handler) describeInstanceTypes(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkFilterNames(filters,
		"auto-recovery-supported", "bare-metal", "burstable-performance-supported", "current-generation",
		"dedicated-hosts-supported", "ebs-info.attachment-limit-type", "ebs-info.maximum-ebs-attachments",
		"ebs-info.ebs-optimized-info.baseline-bandwidth-in-mbps", "ebs-info.ebs-optimized-info.baseline-iops",
		"ebs-info.ebs-optimized-info.baseline-throughput-in-mbps",
		"ebs-info.ebs-optimized-info.maximum-bandwidth-in-mbps", "ebs-info.ebs-optimized-info.maximum-iops",
		"ebs-info.ebs-optimized-info.maximum-throughput-in-mbps", "ebs-info.ebs-optimized-support",
		"ebs-info.encryption-support", "ebs-info.nvme-support", "free-tier-eligible", "hibernation-supported",
		"hypervisor", "instance-storage-info.disk.count", "instance-storage-info.disk.size-in-gb",
		"instance-storage-info.disk.type", "instance-storage-info.encryption-support",
		"instance-storage-info.nvme-support", "instance-storage-info.total-size-in-gb",
		"instance-storage-supported", "instance-type", "memory-info.size-in-mib",
		"network-info.bandwidth-weightings", "network-info.efa-info.maximum-efa-interfaces",
		"network-info.efa-supported", "network-info.ena-support",
		"network-info.flexible-ena-queues-support", "network-info.encryption-in-transit-supported",
		"network-info.ipv4-addresses-per-interface", "network-info.ipv6-addresses-per-interface",
		"network-info.ipv6-supported", "network-info.maximum-network-cards",
		"network-info.maximum-network-interfaces", "network-info.network-performance",
		"nitro-enclaves-support", "nitro-tpm-support", "nitro-tpm-info.supported-versions",
		"processor-info.supported-architecture", "processor-info.sustained-clock-speed-in-ghz",
		"processor-info.supported-features", "reboot-migration-support", "supported-boot-mode",
		"supported-root-device-type", "supported-usage-class", "supported-virtualization-type",
		"vcpu-info.default-cores", "vcpu-info.default-threads-per-core", "vcpu-info.default-vcpus",
		"vcpu-info.valid-cores", "vcpu-info.valid-threads-per-core",
	); err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := boolForm(r, "IncludeUnsupportedInRegion"); err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	want := stringSetOf(indexedStrings(r, "InstanceType"))
	var rows []instanceTypeItem
	for _, typ := range resource.InstanceTypes() {
		row := instanceTypeOf(typ)
		if _, ok := want[row.InstanceType]; len(want) > 0 && !ok {
			continue
		}
		if !filtersMatch(filters, row.filterValue) {
			continue
		}
		rows = append(rows, row)
	}
	rows, next, err := pageRows(rows, page, func(row instanceTypeItem) string { return row.InstanceType })
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, describeInstanceTypesXML{
		InstanceTypes: instanceTypeSetXML{Items: rows}, NextToken: next, RequestID: requestID(r),
	})
}

func stringSetOf(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func instanceTypeOf(typ resource.InstanceType) instanceTypeItem {
	return instanceTypeItem{
		InstanceType:                 typ.Name,
		CurrentGeneration:            true,
		FreeTierEligible:             false,
		SupportedUsageClasses:        stringSetXML{Items: []string{"on-demand"}},
		SupportedRootDeviceTypes:     stringSetXML{Items: []string{"ebs"}},
		SupportedVirtualizationTypes: stringSetXML{Items: []string{"hvm"}},
		BareMetal:                    false,
		ProcessorInfo:                processorInfoXML{SupportedArchitectures: stringSetXML{Items: []string{"x86_64"}}},
		VCpuInfo: vcpuInfoXML{
			DefaultVCpus:          typ.VCPUs,
			DefaultCores:          typ.VCPUs,
			DefaultThreadsPerCore: 1,
		},
		MemoryInfo: memoryInfoXML{SizeInMiB: int64(typ.MemoryMiB)},
	}
}

func (i instanceTypeItem) filterValue(name string) []string {
	switch name {
	case "auto-recovery-supported", "burstable-performance-supported", "dedicated-hosts-supported",
		"hibernation-supported", "instance-storage-supported", "network-info.efa-supported",
		"network-info.encryption-in-transit-supported", "network-info.ipv6-supported":
		return []string{"false"}
	case "bare-metal":
		return []string{strconv.FormatBool(i.BareMetal)}
	case "current-generation":
		return []string{strconv.FormatBool(i.CurrentGeneration)}
	case "free-tier-eligible":
		return []string{strconv.FormatBool(i.FreeTierEligible)}
	case "instance-type":
		return []string{i.InstanceType}
	case "memory-info.size-in-mib":
		return []string{strconv.FormatInt(i.MemoryInfo.SizeInMiB, 10)}
	case "supported-root-device-type":
		return i.SupportedRootDeviceTypes.Items
	case "supported-usage-class":
		return i.SupportedUsageClasses.Items
	case "supported-virtualization-type":
		return i.SupportedVirtualizationTypes.Items
	case "vcpu-info.default-cores", "vcpu-info.valid-cores":
		return []string{strconv.Itoa(i.VCpuInfo.DefaultCores)}
	case "vcpu-info.default-threads-per-core", "vcpu-info.valid-threads-per-core":
		return []string{strconv.Itoa(i.VCpuInfo.DefaultThreadsPerCore)}
	case "vcpu-info.default-vcpus":
		return []string{strconv.Itoa(i.VCpuInfo.DefaultVCpus)}
	case "processor-info.supported-architecture":
		return i.ProcessorInfo.SupportedArchitectures.Items
	case "ebs-info.attachment-limit-type":
		return []string{"shared"}
	case "network-info.bandwidth-weightings":
		return []string{"default"}
	case "network-info.flexible-ena-queues-support", "reboot-migration-support":
		return []string{"unsupported"}
	case "ebs-info.ebs-optimized-info.baseline-bandwidth-in-mbps",
		"ebs-info.ebs-optimized-info.baseline-iops",
		"ebs-info.ebs-optimized-info.baseline-throughput-in-mbps",
		"ebs-info.ebs-optimized-info.maximum-bandwidth-in-mbps",
		"ebs-info.ebs-optimized-info.maximum-iops",
		"ebs-info.ebs-optimized-info.maximum-throughput-in-mbps",
		"ebs-info.ebs-optimized-support", "ebs-info.encryption-support", "ebs-info.nvme-support",
		"ebs-info.maximum-ebs-attachments",
		"hypervisor", "instance-storage-info.disk.count", "instance-storage-info.disk.size-in-gb",
		"instance-storage-info.disk.type", "instance-storage-info.encryption-support",
		"instance-storage-info.nvme-support", "instance-storage-info.total-size-in-gb",
		"network-info.efa-info.maximum-efa-interfaces", "network-info.ena-support",
		"network-info.ipv4-addresses-per-interface", "network-info.ipv6-addresses-per-interface",
		"network-info.maximum-network-cards", "network-info.maximum-network-interfaces",
		"network-info.network-performance", "nitro-enclaves-support", "nitro-tpm-support",
		"nitro-tpm-info.supported-versions",
		"processor-info.sustained-clock-speed-in-ghz", "processor-info.supported-features",
		"supported-boot-mode":
		return nil
	default:
		return nil
	}
}

func (h *handler) describeTags(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkTagFilterNames(filters, "key", "resource-id", "resource-type", "value"); err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var rows []tagDescriptionItem
	instances, err := h.allInstances(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	for _, inst := range instances {
		rows = appendTagDescriptions(rows, "instance", inst.ID.String(), inst.Tags)
	}
	vpcs, err := h.allVpcs(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	for _, vpc := range vpcs {
		rows = appendTagDescriptions(rows, "vpc", vpc.ID.String(), vpc.Tags)
	}
	subnets, err := h.allSubnets(r.Context(), c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	for _, subnet := range subnets {
		rows = appendTagDescriptions(rows, "subnet", subnet.ID.String(), subnet.Tags)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].identity() < rows[j].identity() })
	filtered := rows[:0]
	for _, row := range rows {
		if filtersMatch(filters, row.filterValue) {
			filtered = append(filtered, row)
		}
	}
	filtered, next, err := pageRows(filtered, page, tagDescriptionItem.identity)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, describeTagsXML{
		Tags: tagDescriptionSetXML{Items: filtered}, NextToken: next, RequestID: requestID(r),
	})
}

func appendTagDescriptions(
	rows []tagDescriptionItem, resourceType, id string, tags map[string]string,
) []tagDescriptionItem {
	for key, value := range tags {
		rows = append(rows, tagDescriptionItem{Key: key, ResourceID: id, ResourceType: resourceType, Value: value})
	}
	return rows
}

func (t tagDescriptionItem) identity() string {
	return t.ResourceType + "/" + t.ResourceID + "/" + t.Key
}

func (t tagDescriptionItem) filterValue(name string) []string {
	if key, ok := strings.CutPrefix(name, "tag:"); ok {
		if key == t.Key {
			return []string{t.Value}
		}
		return nil
	}
	switch name {
	case "key":
		return []string{t.Key}
	case "resource-id":
		return []string{t.ResourceID}
	case "resource-type":
		return []string{t.ResourceType}
	case "value":
		return []string{t.Value}
	default:
		return nil
	}
}

func (h *handler) describeVolumesModifications(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.VolumeID](r, "VolumeId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkFilterNames(filters,
		"modification-state", "original-iops", "original-size", "original-volume-type",
		"originalMultiAttachEnabled", "start-time", "target-iops", "target-size",
		"target-volume-type", "targetMultiAttachEnabled", "volume-id",
	); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkModificationFilterValues(filters); err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := boolForm(r, "IncludeManagedResources"); err != nil {
		writeErr(w, r, err)
		return
	}
	for _, f := range filters {
		if f.name != "volume-id" {
			continue
		}
		for _, raw := range f.values {
			id, err := resource.Parse[resource.VolumeID](raw)
			if err != nil {
				writeErr(w, r, err)
				return
			}
			ids = append(ids, id)
		}
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if page.Token != "" {
		writeErr(w, r, resource.Invalid("NextToken", "unknown"))
		return
	}
	if err := h.checkVolumesExist(r.Context(), c, ids); err != nil {
		writeErr(w, r, err)
		return
	}
	// VWS has no modification history to return; vws-storage#157 tracks it.
	writeXML(w, describeVolumesModificationsXML{
		VolumesModifications: volumeModificationSetXML{Items: []volumeModificationItem{}},
		RequestID:            requestID(r),
	})
}

// checkVolumesExist refuses a volume id the caller cannot read, as AWS does
// for a modification query.
func (h *handler) checkVolumesExist(ctx context.Context, c resource.Caller, ids []resource.VolumeID) error {
	if len(ids) == 0 {
		return nil
	}
	want := make(map[resource.VolumeID]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	page, err := h.svc.DescribeVolumes(ctx, c, resource.VolumeQuery{
		IDs: ids, Page: resource.PageRequest{Size: 100},
	})
	if err != nil {
		return err
	}
	found := make(map[resource.VolumeID]struct{}, len(page.Items))
	for _, vol := range page.Items {
		found[vol.ID] = struct{}{}
	}
	if len(found) == len(want) {
		return nil
	}
	// A boot volume is not a DescribeVolumes row, so find it on its instance.
	instances, err := h.allInstances(ctx, c)
	if err != nil {
		return err
	}
	for _, inst := range instances {
		for _, block := range inst.BlockDevices {
			found[block.VolumeID] = struct{}{}
		}
	}
	for id := range want {
		if _, ok := found[id]; !ok {
			return resource.NotFound(resource.KindVolume, id.String())
		}
	}
	return nil
}

func checkModificationFilterValues(filters []queryFilter) error {
	for _, f := range filters {
		for _, value := range f.values {
			switch f.name {
			case "modification-state":
				switch value {
				case "modifying", "optimizing", "completed", "failed":
				default:
					return resource.Invalid("Filter", "unknown modification state")
				}
			case "original-volume-type", "target-volume-type":
				if !resource.VolumeType(value).Valid() {
					return resource.Invalid("Filter", "unknown volume type")
				}
			case "originalMultiAttachEnabled", "targetMultiAttachEnabled":
				if value != "true" && value != "false" {
					return resource.Invalid("Filter", "malformed boolean")
				}
			case "original-iops", "original-size", "target-iops", "target-size":
				if n, err := strconv.ParseInt(value, 10, 64); err != nil || n < 1 {
					return resource.Invalid("Filter", "malformed number")
				}
			case "start-time", "volume-id":
			default:
				return resource.Invalid("Filter", "unsupported")
			}
		}
	}
	return nil
}

func (h *handler) describeAvailabilityZones(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkFilterNames(filters,
		"group-long-name", "group-name", "message", "opt-in-status", "parent-zone-id",
		"parent-zone-name", "region-name", "state", "zone-id", "zone-name", "zone-type",
	); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := optionalBool(r, "AllAvailabilityZones"); err != nil {
		writeErr(w, r, err)
		return
	}
	names := stringSetOf(indexedStrings(r, "ZoneName"))
	ids := stringSetOf(indexedStrings(r, "ZoneId"))
	all := []availabilityZoneItem{{
		ZoneName:           resource.ZoneName,
		ZoneID:             zoneID,
		State:              "available",
		RegionName:         resource.RegionName,
		OptInStatus:        "opt-in-not-required",
		GroupName:          resource.RegionName,
		GroupLongName:      "VWS " + resource.RegionName,
		NetworkBorderGroup: resource.RegionName,
		ZoneType:           "availability-zone",
	}}
	var rows []availabilityZoneItem
	for _, zone := range all {
		if len(names) > 0 {
			if _, ok := names[zone.ZoneName]; !ok {
				continue
			}
		}
		if len(ids) > 0 {
			if _, ok := ids[zone.ZoneID]; !ok {
				continue
			}
		}
		if !filtersMatch(filters, zone.filterValue) {
			continue
		}
		rows = append(rows, zone)
	}
	writeXML(w, describeAvailabilityZonesXML{
		AvailabilityZones: availabilityZoneSetXML{Items: rows}, RequestID: requestID(r),
	})
}

func (z availabilityZoneItem) filterValue(name string) []string {
	switch name {
	case "group-long-name":
		return []string{z.GroupLongName}
	case "group-name":
		return []string{z.GroupName}
	case "message":
		return nil
	case "opt-in-status":
		return []string{z.OptInStatus}
	case "parent-zone-id", "parent-zone-name":
		return nil
	case "region-name":
		return []string{z.RegionName}
	case "state":
		return []string{z.State}
	case "zone-id":
		return []string{z.ZoneID}
	case "zone-name":
		return []string{z.ZoneName}
	case "zone-type":
		return []string{z.ZoneType}
	default:
		return nil
	}
}

func (h *handler) describeRegions(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkFilterNames(filters, "endpoint", "opt-in-status", "region-name"); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := optionalBool(r, "AllRegions"); err != nil {
		writeErr(w, r, err)
		return
	}
	names := stringSetOf(indexedStrings(r, "RegionName"))
	all := []regionItem{{
		RegionName:  resource.RegionName,
		Endpoint:    "ec2." + resource.RegionName + ".vws.internal",
		OptInStatus: "opt-in-not-required",
	}}
	var rows []regionItem
	for _, region := range all {
		if len(names) > 0 {
			if _, ok := names[region.RegionName]; !ok {
				continue
			}
		}
		if !filtersMatch(filters, region.filterValue) {
			continue
		}
		rows = append(rows, region)
	}
	writeXML(w, describeRegionsXML{Regions: regionSetXML{Items: rows}, RequestID: requestID(r)})
}

func (r regionItem) filterValue(name string) []string {
	switch name {
	case "endpoint":
		return []string{r.Endpoint}
	case "opt-in-status":
		return []string{r.OptInStatus}
	case "region-name":
		return []string{r.RegionName}
	default:
		return nil
	}
}

func (h *handler) describeRouteTables(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkTagFilterNames(filters,
		"association.gateway-id", "association.route-table-association-id",
		"association.route-table-id", "association.subnet-id", "association.main",
		"owner-id", "route-table-id", "route.destination-cidr-block",
		"route.destination-ipv6-cidr-block", "route.destination-prefix-list-id",
		"route.egress-only-internet-gateway-id", "route.gateway-id", "route.instance-id",
		"route.nat-gateway-id", "route.transit-gateway-id", "route.origin", "route.state",
		"route.vpc-peering-connection-id", "tag", "tag-key", "vpc-id",
	); err != nil {
		writeErr(w, r, err)
		return
	}
	if ids := indexedStrings(r, "RouteTableId"); len(ids) > 0 {
		raw := ids[0]
		if !validRouteTableID(raw) {
			writeErr(w, r, resource.Invalid("routeTableId", "malformed"))
			return
		}
		writeErr(w, r, routeTableNotFound(raw))
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if page.Token != "" {
		writeErr(w, r, resource.Invalid("NextToken", "unknown"))
		return
	}
	// VWS has no route table model, so every VPC's main route table is absent.
	// popododo0720/vws-console-api#206 and #207 track the model.
	writeXML(w, describeRouteTablesXML{
		RouteTables: routeTableSetXML{Items: []routeTableItem{}}, RequestID: requestID(r),
	})
}

// routeTableNotFound reports a route table id VWS cannot serve. VWS has no
// route table model; the EC2 code is InvalidRouteTableID.NotFound.
func routeTableNotFound(id string) *resource.Error {
	return &resource.Error{
		Code: resource.CodeNotFound, Field: "routeTableId", ID: id,
		Message: "The routeTable ID '" + id + "' does not exist.",
	}
}

func validRouteTableID(id string) bool {
	rest, ok := strings.CutPrefix(id, "rtb-")
	if !ok || len(rest) < 8 || len(rest) > 17 {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// boolForm reads an EC2 boolean parameter. Left out is false. boto3 sends
// IncludeAllInstances as includeAllInstances, so the lower camel form counts.
func boolForm(r *http.Request, key string) (bool, error) {
	raw := r.Form.Get(key)
	if raw == "" {
		raw = r.Form.Get(strings.ToLower(key[:1]) + key[1:])
	}
	switch raw {
	case "":
		return false, nil
	case "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, resource.Invalid(key, "malformed")
	}
}
