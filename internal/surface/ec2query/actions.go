package ec2query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) createVpc(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if raw := r.Form.Get("InstanceTenancy"); raw != "" && raw != "default" {
		writeErr(w, r, resource.Invalid("InstanceTenancy", "unsupported"))
		return
	}
	tags, err := tagSpecificationsFor(r, "vpc")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateVpc(r.Context(), c, token, resource.CreateVpcRequest{Cidr: r.Form.Get("CidrBlock"), Tags: tags})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, createVpcXML{RequestID: requestID(r), Vpc: vpcXML(acc.Items[0])})
}

func (h *handler) describeVpcs(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.VpcID](r, "VpcId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	filters, err := queryFilters(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := checkTagFilterNames(filters); err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var rows []resource.Vpc
	next := ""
	if len(filters) == 0 {
		out, err := h.svc.DescribeVpcs(r.Context(), c, resource.VpcQuery{IDs: ids, Page: page})
		if err != nil {
			writeErr(w, r, err)
			return
		}
		rows, next = out.Items, out.NextToken
	} else {
		rows, err = collectPages(r.Context(), c, func(p resource.PageRequest) resource.VpcQuery {
			return resource.VpcQuery{IDs: ids, Page: p}
		}, h.svc.DescribeVpcs)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		rows = filterRows(rows, filters, vpcFilterValue)
		rows, next, err = pageRows(rows, page, func(v resource.Vpc) string { return v.ID.String() })
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	var items []vpcItem
	for _, vpc := range rows {
		items = append(items, vpcXML(vpc))
	}
	writeXML(w, describeVpcsXML{RequestID: requestID(r), NextToken: next, Vpcs: struct {
		Items []vpcItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) deleteVpc(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.VpcID](r.Form.Get("VpcId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.DeleteVpc(r.Context(), c, token, resource.DeleteVpcRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteVpcXML{RequestID: requestID(r), Return: true})
}

func (h *handler) createVolume(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var snap resource.SnapshotID
	if raw := r.Form.Get("SnapshotId"); raw != "" {
		if snap, err = resource.Parse[resource.SnapshotID](raw); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	// Size may be left out when SnapshotId is given; it is then the snapshot size.
	var size int64
	if raw := r.Form.Get("Size"); raw != "" || snap.IsZero() {
		if size, err = strconv.ParseInt(raw, 10, 64); err != nil {
			writeErr(w, r, resource.Invalid("Size", "malformed"))
			return
		}
	}
	iops, err := optionalInt(r, "Iops")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	throughput, err := optionalInt(r, "Throughput")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tags, err := tagSpecificationsFor(r, "volume")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateVolume(r.Context(), c, token, resource.CreateVolumeRequest{
		SizeGiB: size, Zone: r.Form.Get("AvailabilityZone"), Type: resource.VolumeType(r.Form.Get("VolumeType")),
		SnapshotID: snap, Iops: iops, Throughput: throughput, Tags: tags,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, volumeCreatedXML(requestID(r), acc.Items[0]))
}

// optionalInt reads a positive integer parameter. Left out is 0.
func optionalInt(r *http.Request, key string) (int64, error) {
	raw := r.Form.Get(key)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, resource.Invalid(key, "Value ("+raw+") for parameter "+strings.ToLower(key[:1])+key[1:]+" is invalid.")
	}
	return n, nil
}

func (h *handler) describeVolumes(w http.ResponseWriter, r *http.Request, c resource.Caller) {
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
	if err := checkTagFilterNames(filters, "attachment.instance-id"); err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var rows []resource.Volume
	next := ""
	if len(filters) == 0 {
		out, err := h.svc.DescribeVolumes(r.Context(), c, resource.VolumeQuery{IDs: ids, Page: page})
		if err != nil {
			writeErr(w, r, err)
			return
		}
		rows, next = out.Items, out.NextToken
	} else {
		rows, err = collectPages(r.Context(), c, func(p resource.PageRequest) resource.VolumeQuery {
			return resource.VolumeQuery{IDs: ids, Page: p}
		}, h.svc.DescribeVolumes)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		rows = filterRows(rows, filters, volumeFilterValue)
		rows, next, err = pageRows(rows, page, func(v resource.Volume) string { return v.ID.String() })
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	var items []volumeItem
	for _, vol := range rows {
		items = append(items, volumeXML(vol))
	}
	writeXML(w, describeVolumesXML{RequestID: requestID(r), NextToken: next, Volumes: struct {
		Items []volumeItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) detachVolume(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	vol, err := resource.Parse[resource.VolumeID](r.Form.Get("VolumeId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var inst resource.InstanceID
	if raw := r.Form.Get("InstanceId"); raw != "" {
		inst, err = resource.Parse[resource.InstanceID](raw)
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	force, err := parseOptionalBool(r.Form.Get("Force"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DetachVolume(r.Context(), c, token, resource.DetachVolumeRequest{
		VolumeID: vol, InstanceID: inst, Device: r.Form.Get("Device"), Force: force,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	item := acc.Items[0]
	writeXML(w, detachVolumeXML{
		RequestID: requestID(r), VolumeID: item.VolumeID.String(), InstanceID: item.InstanceID.String(),
		Device: item.Device, Status: string(item.Status), AttachTime: awsTime(item.AttachTime),
	})
}

func parseOptionalBool(raw string) (bool, error) {
	switch raw {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, resource.Invalid("Force", "malformed")
	}
}

func (h *handler) attachVolume(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	vol, err := resource.Parse[resource.VolumeID](r.Form.Get("VolumeId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	inst, err := resource.Parse[resource.InstanceID](r.Form.Get("InstanceId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AttachVolume(r.Context(), c, token, resource.AttachVolumeRequest{
		VolumeID: vol, InstanceID: inst, Device: r.Form.Get("Device"),
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	item := acc.Items[0]
	// EC2 answers an accepted attach as attaching; DescribeVolumes moves it
	// to attached.
	status := item.AttachState
	if status == "" {
		status = resource.AttachmentAttaching
	}
	writeXML(w, attachVolumeXML{
		RequestID: requestID(r), VolumeID: item.ID.String(), InstanceID: item.InstanceID.String(),
		Device: item.Device, Status: string(status),
		// The accept is when the attachment initiated, for a backend that
		// records no attach time.
		AttachTime: awsTime(attachTimeOr(item.AttachTime, acc.Operation.CreateTime)),
	})
}

func (h *handler) deleteVolume(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.Form.Get("VolumeId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.DeleteVolume(r.Context(), c, token, resource.DeleteVolumeRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteVolumeXML{RequestID: requestID(r), Return: true})
}

// modifyVolume changes a volume's Size, VolumeType, Iops and Throughput in
// one request.
func (h *handler) modifyVolume(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.Form.Get("VolumeId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeType(r.Form.Get("VolumeType"))}
	for _, f := range []struct {
		key string
		dst *int64
	}{{"Size", &req.SizeGiB}, {"Iops", &req.Iops}, {"Throughput", &req.Throughput}} {
		if *f.dst, err = optionalInt(r, f.key); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	before, err := h.svc.DescribeVolumes(r.Context(), c, resource.VolumeQuery{IDs: []resource.VolumeID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(before.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindVolume, id.String()))
		return
	}
	orig := before.Items[0]
	acc, err := h.svc.ModifyVolume(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	item := acc.Items[0]
	writeXML(w, modifyVolumeXML{RequestID: requestID(r), Modification: volumeModificationXML{
		VolumeID: item.ID.String(), State: "modifying",
		TargetSize: item.SizeGiB, OriginalSize: orig.SizeGiB,
		TargetType: string(item.Type), OriginalType: string(orig.Type),
		TargetIops: item.ReportedIops(), OriginalIops: orig.ReportedIops(),
		TargetThroughput: item.Throughput, OriginalThroughput: orig.Throughput,
		Start: acc.Operation.CreateTime.UTC().Format(time.RFC3339),
	}})
}

func (h *handler) createSecurityGroup(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if r.Form.Get("GroupDescription") == "" {
		writeErr(w, r, resource.Invalid("GroupDescription", "required"))
		return
	}
	vpc, err := resource.Parse[resource.VpcID](r.Form.Get("VpcId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateSecurityGroup(r.Context(), c, token, resource.CreateSecurityGroupRequest{
		Name: r.Form.Get("GroupName"), VpcID: vpc,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, createGroupXML{RequestID: requestID(r), GroupID: acc.Items[0].ID.String()})
}

func (h *handler) authorizeIngress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.SecurityGroupID](r.Form.Get("GroupId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	perms, err := ipPermissions(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	rules, err := resource.IngressRules(perms)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.AuthorizeSecurityGroupIngress(r.Context(), c, token, resource.AuthorizeSecurityGroupIngressRequest{
		ID: id, Rules: rules,
	}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, authorizeXML{RequestID: requestID(r), Return: true})
}

func (h *handler) revokeIngress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.SecurityGroupID](r.Form.Get("GroupId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	rule, err := ingressRule(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.RevokeSecurityGroupIngress(r.Context(), c, token, resource.RevokeSecurityGroupIngressRequest{
		ID: id, Rule: rule,
	}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, revokeXML{RequestID: requestID(r), Return: true})
}

func (h *handler) startInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	h.changeInstances(w, r, "StartInstancesResponse", func(ctx context.Context, token resource.ClientToken, ids []resource.InstanceID) (resource.Accepted[resource.InstanceStateChange], error) {
		return h.svc.StartInstances(ctx, c, token, resource.StartInstancesRequest{IDs: ids})
	})
}

func (h *handler) terminateInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	h.changeInstances(w, r, "TerminateInstancesResponse", func(ctx context.Context, token resource.ClientToken, ids []resource.InstanceID) (resource.Accepted[resource.InstanceStateChange], error) {
		return h.svc.TerminateInstances(ctx, c, token, resource.TerminateInstancesRequest{IDs: ids})
	})
}

func (h *handler) changeInstances(w http.ResponseWriter, r *http.Request, root string, call func(context.Context, resource.ClientToken, []resource.InstanceID) (resource.Accepted[resource.InstanceStateChange], error)) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := call(r.Context(), token, ids)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []stateItem
	for _, ch := range acc.Items {
		items = append(items, stateItem{
			InstanceID: ch.ID.String(), CurrentState: stateXMLOf(ch.Current), PreviousState: stateXMLOf(ch.Previous),
		})
	}
	writeXML(w, instancesChangedXML{XMLName: xml.Name{Local: root}, RequestID: requestID(r), Instances: struct {
		Items []stateItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) describeImages(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	if err := optionalBool(r, "IncludeDeprecated"); err != nil {
		writeErr(w, r, err)
		return
	}
	if err := optionalBool(r, "IncludeDisabled"); err != nil {
		writeErr(w, r, err)
		return
	}
	owner, ok := ownerFilter(r, c.Account)
	if !ok || !selectsCaller(indexedStrings(r, "ExecutableBy"), c.Account) {
		writeXML(w, describeImagesXML{RequestID: requestID(r)})
		return
	}
	ids, err := indexedIDs[resource.ImageID](r, "ImageId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeImages(r.Context(), c, resource.ImageQuery{IDs: ids, Owner: owner, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []imageItem
	for _, img := range page.Items {
		items = append(items, imageXML(img))
	}
	writeXML(w, describeImagesXML{RequestID: requestID(r), NextToken: page.NextToken, Images: struct {
		Items []imageItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) createKeyPair(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateKeyPair(r.Context(), c, token, resource.CreateKeyPairRequest{
		Name: r.Form.Get("KeyName"), Type: resource.KeyType(r.Form.Get("KeyType")),
		Format: resource.KeyFormat(r.Form.Get("KeyFormat")),
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	key := acc.Items[0]
	writeXML(w, createKeyXML{
		RequestID: requestID(r), KeyName: key.Name, KeyFingerprint: key.Fingerprint,
		KeyMaterial: key.Material, KeyPairID: key.ID.String(),
	})
}

// maxQueryIndex bounds N in IpPermissions.N and M in its source lists. A
// request adds at most resource.MaxIngressRules rules, so a larger index
// cannot name a rule that fits.
const maxQueryIndex = resource.MaxIngressRules

// ipPermissions reads IpPermissions.N in index order, or the top-level
// IpProtocol, FromPort, ToPort and CidrIp as one permission. A request that
// sends both is refused rather than one of them being dropped.
func ipPermissions(r *http.Request) ([]resource.IPPermission, error) {
	type permissionForm struct {
		fields map[string]string
		lists  map[string]map[int]map[string]string
	}
	forms := map[int]*permissionForm{}
	legacy := false
	for key := range r.Form {
		if legacyRuleField(key) {
			legacy = true
			continue
		}
		n, field, ok := ipPermissionKey(key)
		if !ok {
			continue
		}
		form := forms[n]
		if form == nil {
			form = &permissionForm{fields: map[string]string{}, lists: map[string]map[int]map[string]string{}}
			forms[n] = form
		}
		list, m, leaf, ok := permissionSource(field)
		if !ok {
			form.fields[field] = r.Form.Get(key)
			continue
		}
		if form.lists[list] == nil {
			form.lists[list] = map[int]map[string]string{}
		}
		if form.lists[list][m] == nil {
			form.lists[list][m] = map[string]string{}
		}
		form.lists[list][m][leaf] = r.Form.Get(key)
	}
	if legacy {
		if len(forms) > 0 {
			return nil, resource.InvalidCombination("IpPermissions",
				"The parameter IpPermissions cannot be used with IpProtocol, FromPort, ToPort or CidrIp.")
		}
		from, err := sentPort(r.Form.Get("FromPort"))
		if err != nil {
			return nil, err
		}
		to, err := sentPort(r.Form.Get("ToPort"))
		if err != nil {
			return nil, err
		}
		perm := resource.IPPermission{Protocol: r.Form.Get("IpProtocol"), FromPort: from, ToPort: to}
		if cidr := r.Form.Get("CidrIp"); cidr != "" {
			perm.IPRanges = []resource.IPRange{{CidrIP: cidr}}
		}
		return []resource.IPPermission{perm}, nil
	}
	perms := make([]resource.IPPermission, 0, len(forms))
	for _, n := range slices.Sorted(maps.Keys(forms)) {
		form := forms[n]
		from, err := sentPort(form.fields["FromPort"])
		if err != nil {
			return nil, err
		}
		to, err := sentPort(form.fields["ToPort"])
		if err != nil {
			return nil, err
		}
		perm := resource.IPPermission{Protocol: form.fields["IpProtocol"], FromPort: from, ToPort: to}
		for _, src := range inOrder(form.lists["IpRanges"]) {
			perm.IPRanges = append(
				perm.IPRanges,
				resource.IPRange{CidrIP: src["CidrIp"], Description: src["Description"]},
			)
		}
		for _, src := range inOrder(form.lists["Ipv6Ranges"]) {
			perm.IPv6Ranges = append(
				perm.IPv6Ranges,
				resource.IPv6Range{CidrIPv6: src["CidrIpv6"], Description: src["Description"]},
			)
		}
		for _, src := range inOrder(form.lists["Groups"]) {
			perm.UserIDGroupPairs = append(perm.UserIDGroupPairs, resource.UserIDGroupPair{
				Description: src["Description"], GroupID: src["GroupId"], GroupName: src["GroupName"],
				PeeringStatus: src["PeeringStatus"], UserID: src["UserId"], VpcID: src["VpcId"],
				VpcPeeringConnectionID: src["VpcPeeringConnectionId"],
			})
		}
		for _, src := range inOrder(form.lists["PrefixListIds"]) {
			perm.PrefixListIDs = append(perm.PrefixListIDs, resource.PrefixListID{
				Description: src["Description"], PrefixListID: src["PrefixListId"],
			})
		}
		perms = append(perms, perm)
	}
	return perms, nil
}

func inOrder(byIndex map[int]map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(byIndex))
	for _, m := range slices.Sorted(maps.Keys(byIndex)) {
		out = append(out, byIndex[m])
	}
	return out
}

func ingressRule(r *http.Request) (resource.IngressRule, error) {
	protocol := r.Form.Get("IpPermissions.1.IpProtocol")
	fromRaw := r.Form.Get("IpPermissions.1.FromPort")
	toRaw := r.Form.Get("IpPermissions.1.ToPort")
	cidr := r.Form.Get("IpPermissions.1.IpRanges.1.CidrIp")
	if cidr == "" {
		cidr = r.Form.Get("IpPermissions.1.CidrIp")
	}
	if protocol == "" {
		protocol = r.Form.Get("IpProtocol")
		fromRaw = r.Form.Get("FromPort")
		toRaw = r.Form.Get("ToPort")
		cidr = r.Form.Get("CidrIp")
	}
	from, err := portValue(fromRaw)
	if err != nil {
		return resource.IngressRule{}, err
	}
	to, err := portValue(toRaw)
	if err != nil {
		return resource.IngressRule{}, err
	}
	return resource.IngressRule{Protocol: protocol, FromPort: from, ToPort: to, Cidr: cidr}, nil
}

// sentPort reads a port of an IpPermissions entry. Nil means it was not sent,
// which resource.IngressRules refuses for icmp.
func sentPort(raw string) (*int, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // a nil port is one the request did not send
	}
	n, err := portValue(raw)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func portValue(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, resource.Invalid("FromPort", "malformed")
	}
	return n, nil
}

// tagTargets are the ResourceId.N of CreateTags or DeleteTags, by kind.
type tagTargets struct {
	insts []resource.InstanceID
	vpcs  []resource.VpcID
	subs  []resource.SubnetID
	vols  []resource.VolumeID
}

// kinds counts the resource kinds named.
func (t tagTargets) kinds() int {
	n := 0
	for _, k := range []int{len(t.insts), len(t.vpcs), len(t.subs), len(t.vols)} {
		if k > 0 {
			n++
		}
	}
	return n
}

// parseTagTargets reads ResourceId.N. Other resource kinds fail with
// InvalidParameterValue, and an ID of a taggable kind that does not parse
// with InvalidID.
// A direct VPC or subnet is read-only. The request fans out per kind, so
// it is refused here, before any kind is written.
func parseTagTargets(r *http.Request) (tagTargets, error) {
	var t tagTargets
	for _, raw := range indexedStrings(r, "ResourceId") {
		switch {
		case strings.HasPrefix(raw, "i-"):
			id, err := resource.Parse[resource.InstanceID](raw)
			if err != nil {
				return tagTargets{}, resource.InvalidTaggedID(raw)
			}
			t.insts = append(t.insts, id)
		case strings.HasPrefix(raw, "vpc-"):
			id, err := resource.Parse[resource.VpcID](raw)
			if err != nil {
				return tagTargets{}, resource.InvalidTaggedID(raw)
			}
			if resource.IsDirectVpc(id) {
				return tagTargets{}, resource.DirectReadOnly()
			}
			t.vpcs = append(t.vpcs, id)
		case strings.HasPrefix(raw, "subnet-"):
			id, err := resource.Parse[resource.SubnetID](raw)
			if err != nil {
				return tagTargets{}, resource.InvalidTaggedID(raw)
			}
			if resource.IsDirectSubnet(id) {
				return tagTargets{}, resource.DirectReadOnly()
			}
			t.subs = append(t.subs, id)
		case strings.HasPrefix(raw, "vol-"):
			id, err := resource.Parse[resource.VolumeID](raw)
			if err != nil {
				return tagTargets{}, resource.InvalidTaggedID(raw)
			}
			t.vols = append(t.vols, id)
		default:
			return tagTargets{}, resource.Invalid("ResourceId", "only instances, VPCs, subnets and volumes can be tagged")
		}
	}
	if t.kinds() == 0 {
		return tagTargets{}, resource.Invalid("ResourceId", "required")
	}
	return t, nil
}

// checkPart normalizes one kind's part of a request that fans out per kind.
// Every part is checked before the first is sent, so a request that fails
// validation in a later kind writes nothing.
func checkPart[I any, R resource.Request[R]](ids []I, req R) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := req.Normalize()
	return err
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// partToken is the client token for one kind of a request that fans out:
// the caller's own with one kind, else one derived from it per kind.
func partToken(token resource.ClientToken, kinds int, kind string) (resource.ClientToken, error) {
	if token.IsZero() || kinds == 1 {
		return token, nil
	}
	return derivedToken(token, kind)
}

// createTags tags instances, VPCs and subnets, which may be mixed in one call
// (parseTagTargets). Each kind is its own
// backend mutation; with a ClientToken and more than one kind, each kind gets
// a token derived from the caller's, so a retry replays every part.
func (h *handler) createTags(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	t, err := parseTagTargets(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tags := map[string]string{}
	for i := 1; i <= 50; i++ {
		prefix := "Tag." + strconv.Itoa(i) + "."
		k, v := r.Form.Get(prefix+"Key"), r.Form.Get(prefix+"Value")
		if k == "" && v == "" {
			continue
		}
		if k == "" {
			writeErr(w, r, resource.Invalid(prefix+"Key", "required"))
			return
		}
		tags[k] = v
	}
	kinds := t.kinds()
	instReq := resource.CreateTagsRequest{IDs: t.insts, Tags: tags}
	vpcReq := resource.TagVpcsRequest{IDs: t.vpcs, Tags: tags}
	subReq := resource.TagSubnetsRequest{IDs: t.subs, Tags: tags}
	volReq := resource.TagVolumesRequest{IDs: t.vols, Tags: tags}
	if err := firstErr(
		checkPart(t.insts, instReq), checkPart(t.vpcs, vpcReq), checkPart(t.subs, subReq), checkPart(t.vols, volReq),
	); err != nil {
		writeErr(w, r, err)
		return
	}
	if len(t.insts) > 0 {
		pt, err := partToken(token, kinds, "instance")
		if err == nil {
			_, err = h.svc.CreateTags(r.Context(), c, pt, instReq)
		}
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if len(t.vpcs) > 0 {
		pt, err := partToken(token, kinds, "vpc")
		if err == nil {
			_, err = h.svc.TagVpcs(r.Context(), c, pt, vpcReq)
		}
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if len(t.subs) > 0 {
		pt, err := partToken(token, kinds, "subnet")
		if err == nil {
			_, err = h.svc.TagSubnets(r.Context(), c, pt, subReq)
		}
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if len(t.vols) > 0 {
		pt, err := partToken(token, kinds, "volume")
		if err == nil {
			_, err = h.svc.TagVolumes(r.Context(), c, pt, volReq)
		}
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	writeXML(w, createTagsXML{RequestID: requestID(r), Return: true})
}

// tagSelectors reads Tag.N of DeleteTags. Tag.N.Value present, even empty,
// deletes the key only with that value; Tag.N.Value absent deletes the key
// whatever its value. No Tag.N at all deletes every user tag.
func tagSelectors(r *http.Request) ([]resource.TagSelector, error) {
	var out []resource.TagSelector
	for i := 1; i <= maxDeleteTagIndex; i++ {
		prefix := "Tag." + strconv.Itoa(i) + "."
		keys, hasKey := r.Form[prefix+"Key"]
		values, hasValue := r.Form[prefix+"Value"]
		if !hasKey && !hasValue {
			continue
		}
		if !hasKey || keys[0] == "" {
			return nil, resource.Invalid(prefix+"Key", "required")
		}
		sel := resource.TagSelector{Key: keys[0]}
		if hasValue {
			v := values[0]
			sel.Value = &v
		}
		out = append(out, sel)
	}
	return out, nil
}

// maxDeleteTagIndex bounds Tag.N on DeleteTags, as allowDeleteTags does.
const maxDeleteTagIndex = resource.MaxTags

// deleteTags deletes tags from instances, VPCs and subnets, mixed as in
// createTags. Deleting a tag the resource does not have is not an error.
func (h *handler) deleteTags(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	t, err := parseTagTargets(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	sel, err := tagSelectors(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(t.vols) > 0 {
		writeErr(w, r, resource.Invalid("ResourceId", "only instances, VPCs and subnets can be untagged"))
		return
	}
	instReq := resource.DeleteTagsRequest{IDs: t.insts, Tags: sel}
	vpcReq := resource.UntagVpcsRequest{IDs: t.vpcs, Tags: sel}
	subReq := resource.UntagSubnetsRequest{IDs: t.subs, Tags: sel}
	if err := firstErr(checkPart(t.insts, instReq), checkPart(t.vpcs, vpcReq), checkPart(t.subs, subReq)); err != nil {
		writeErr(w, r, err)
		return
	}
	var token resource.ClientToken
	if len(t.insts) > 0 {
		if _, err := h.svc.DeleteTags(r.Context(), c, token, instReq); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if len(t.vpcs) > 0 {
		if _, err := h.svc.UntagVpcs(r.Context(), c, token, vpcReq); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	if len(t.subs) > 0 {
		if _, err := h.svc.UntagSubnets(r.Context(), c, token, subReq); err != nil {
			writeErr(w, r, err)
			return
		}
	}
	writeXML(w, deleteTagsXML{RequestID: requestID(r), Return: true})
}

// derivedToken is a client token for one part of a request that fans out.
func derivedToken(token resource.ClientToken, part string) (resource.ClientToken, error) {
	sum := sha256.Sum256([]byte(token.String() + "\x00" + part))
	out, err := resource.Parse[resource.ClientToken]("t-" + hex.EncodeToString(sum[:16]))
	if err != nil {
		return resource.ClientToken{}, resource.Internal(err)
	}
	return out, nil
}
