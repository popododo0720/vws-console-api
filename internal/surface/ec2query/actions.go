package ec2query

import (
	"context"
	"encoding/xml"
	"net/http"
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
	acc, err := h.svc.CreateVpc(r.Context(), c, token, resource.CreateVpcRequest{Cidr: r.Form.Get("CidrBlock")})
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
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeVpcs(r.Context(), c, resource.VpcQuery{IDs: ids, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []vpcItem
	for _, vpc := range page.Items {
		items = append(items, vpcXML(vpc))
	}
	writeXML(w, describeVpcsXML{RequestID: requestID(r), NextToken: page.NextToken, Vpcs: struct {
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
	acc, err := h.svc.CreateVolume(r.Context(), c, token, resource.CreateVolumeRequest{
		SizeGiB: size, Zone: r.Form.Get("AvailabilityZone"), Type: resource.VolumeType(r.Form.Get("VolumeType")),
		SnapshotID: snap,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, volumeCreatedXML(requestID(r), acc.Items[0]))
}

func (h *handler) describeVolumes(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.VolumeID](r, "VolumeId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeVolumes(r.Context(), c, resource.VolumeQuery{IDs: ids, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []volumeItem
	for _, vol := range page.Items {
		items = append(items, volumeXML(vol))
	}
	writeXML(w, describeVolumesXML{RequestID: requestID(r), NextToken: page.NextToken, Volumes: struct {
		Items []volumeItem `xml:"item"`
	}{Items: items}})
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
	writeXML(w, attachVolumeXML{
		RequestID: requestID(r), VolumeID: item.ID.String(), InstanceID: item.InstanceID.String(),
		Device: item.Device, Status: "attached",
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

// modifyVolume grows a volume. VolumeType, Iops and Throughput are not
// accepted fields, so the request fails before reaching the backend.
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
	size, err := strconv.ParseInt(r.Form.Get("Size"), 10, 64)
	if err != nil {
		writeErr(w, r, resource.Invalid("Size", "required"))
		return
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
	acc, err := h.svc.ModifyVolume(r.Context(), c, token, resource.ModifyVolumeRequest{ID: id, SizeGiB: size})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	item := acc.Items[0]
	writeXML(w, modifyVolumeXML{RequestID: requestID(r), Modification: volumeModificationXML{
		VolumeID: item.ID.String(), State: "modifying",
		TargetSize: item.SizeGiB, OriginalSize: orig.SizeGiB,
		TargetType: string(item.Type), OriginalType: string(orig.Type),
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
	rule, err := ingressRule(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.AuthorizeSecurityGroupIngress(r.Context(), c, token, resource.AuthorizeSecurityGroupIngressRequest{
		ID: id, Rule: rule,
	}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, authorizeXML{RequestID: requestID(r), Return: true})
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
	if !ownerSelectsCaller(r, c.Account) || !selectsCaller(indexedStrings(r, "ExecutableBy"), c.Account) {
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
	page, err := h.svc.DescribeImages(r.Context(), c, resource.ImageQuery{IDs: ids, Page: pageReq})
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
	acc, err := h.svc.CreateKeyPair(r.Context(), c, token, resource.CreateKeyPairRequest{Name: r.Form.Get("KeyName")})
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

// createTags tags instances. Other resource kinds fail with
// InvalidParameterValue: only the compute backend stores tags today.
func (h *handler) createTags(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var ids []resource.InstanceID
	for _, raw := range indexedStrings(r, "ResourceId") {
		if !strings.HasPrefix(raw, "i-") {
			writeErr(w, r, resource.Invalid("ResourceId", "only instances can be tagged"))
			return
		}
		id, err := resource.Parse[resource.InstanceID](raw)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		ids = append(ids, id)
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
	if _, err := h.svc.CreateTags(r.Context(), c, token, resource.CreateTagsRequest{IDs: ids, Tags: tags}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, createTagsXML{RequestID: requestID(r), Return: true})
}
