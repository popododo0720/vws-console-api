// Package ec2query serves a small EC2 Query entry point.
// Actions parse into the resource model and render EC2-shaped XML.
// The listener is dedicated to this protocol so the path does not have to be sniffed.
package ec2query

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Version is the query version this entry point accepts.
const Version = "2016-11-15"

// Config wires the query surface.
type Config struct {
	Service  *cloud.Service
	Verifier *sigv4.Verifier
}

// New returns the query handler.
func New(cfg Config) http.Handler {
	h := &handler{svc: cfg.Service, verifier: cfg.Verifier}
	return http.HandlerFunc(h.serve)
}

type handler struct {
	svc      *cloud.Service
	verifier *sigv4.Verifier
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	if h.verifier == nil {
		writeErr(w, r, resource.Unauthenticated("missing signature"))
		return
	}
	caller, err := h.verifier.Verify(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, r, resource.Invalid("body", "malformed form"))
		return
	}
	for k, vs := range r.Form {
		if len(vs) > 1 {
			writeErr(w, r, resource.Invalid(k, "repeated"))
			return
		}
	}
	if r.Form.Get("Version") != Version {
		writeErr(w, r, resource.Invalid("Version", "unsupported"))
		return
	}
	action := r.Form.Get("Action")
	if err := rejectUnknown(r, action); err != nil {
		writeErr(w, r, err)
		return
	}
	if strings.HasPrefix(action, "Describe") {
		if err := rejectDryRun(r); err != nil {
			writeErr(w, r, err)
			return
		}
		if action != "DescribeInstances" {
			if err := rejectPlainFilters(r); err != nil {
				writeErr(w, r, err)
				return
			}
		}
	}
	switch action {
	case resource.ActionRunInstances.String():
		h.runInstances(w, r, caller)
	case resource.ActionStopInstances.String():
		h.stopInstances(w, r, caller)
	case resource.ActionCreateSubnet.String():
		h.createSubnet(w, r, caller)
	case resource.ActionCreateVpc.String():
		h.createVpc(w, r, caller)
	case resource.ActionDeleteVpc.String():
		h.deleteVpc(w, r, caller)
	case resource.ActionCreateVolume.String():
		h.createVolume(w, r, caller)
	case resource.ActionAttachVolume.String():
		h.attachVolume(w, r, caller)
	case resource.ActionDeleteVolume.String():
		h.deleteVolume(w, r, caller)
	case resource.ActionCreateSecurityGroup.String():
		h.createSecurityGroup(w, r, caller)
	case resource.ActionAuthorizeSecurityGroupIngress.String():
		h.authorizeIngress(w, r, caller)
	case resource.ActionStartInstances.String():
		h.startInstances(w, r, caller)
	case resource.ActionTerminateInstances.String():
		h.terminateInstances(w, r, caller)
	case resource.ActionCreateKeyPair.String():
		h.createKeyPair(w, r, caller)
	case resource.ActionDeleteKeyPair.String():
		h.deleteKeyPair(w, r, caller)
	case resource.ActionDeleteSecurityGroup.String():
		h.deleteSecurityGroup(w, r, caller)
	case resource.ActionDeleteSubnet.String():
		h.deleteSubnet(w, r, caller)
	case resource.ActionAllocateAddress.String():
		h.allocateAddress(w, r, caller)
	case resource.ActionReleaseAddress.String():
		h.releaseAddress(w, r, caller)
	case resource.ActionCreateSnapshot.String():
		h.createSnapshot(w, r, caller)
	case resource.ActionDeleteSnapshot.String():
		h.deleteSnapshot(w, r, caller)
	case "DescribeInstances":
		h.describeInstances(w, r, caller)
	case "DescribeSubnets":
		h.describeSubnets(w, r, caller)
	case "DescribeVpcs":
		h.describeVpcs(w, r, caller)
	case "DescribeVolumes":
		h.describeVolumes(w, r, caller)
	case "DescribeImages":
		h.describeImages(w, r, caller)
	case "DescribeKeyPairs":
		h.describeKeyPairs(w, r, caller)
	case "DescribeSecurityGroups":
		h.describeSecurityGroups(w, r, caller)
	case "DescribeAddresses":
		h.describeAddresses(w, r, caller)
	case "DescribeSnapshots":
		h.describeSnapshots(w, r, caller)
	default:
		writeErr(w, r, resource.Unimplemented(action))
	}
}

func (h *handler) runInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := clientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	img, err := resource.Parse[resource.ImageID](r.Form.Get("ImageId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	sub, err := resource.Parse[resource.SubnetID](r.Form.Get("SubnetId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	count, err := exactCount(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tags, err := mergeTags(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.RunInstances(r.Context(), c, token, resource.RunInstancesRequest{
		ImageID: img, InstanceType: r.Form.Get("InstanceType"), SubnetID: sub, Count: count, Tags: tags,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, runInstancesXML{
		RequestID: requestID(r), ReservationID: acc.Items[0].ReservationID.String(),
		Instances: instanceItems(acc.Items),
	})
}

func (h *handler) stopInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
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
	acc, err := h.svc.StopInstances(r.Context(), c, token, resource.StopInstancesRequest{IDs: ids})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []stateItem
	for _, ch := range acc.Items {
		items = append(items, stateItem{
			InstanceID:    ch.ID.String(),
			CurrentState:  stateXMLOf(ch.Current),
			PreviousState: stateXMLOf(ch.Previous),
		})
	}
	writeXML(w, stopInstancesXML{RequestID: requestID(r), Instances: struct {
		Items []stateItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) createSubnet(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var vpc resource.VpcID
	if raw := r.Form.Get("VpcId"); raw != "" {
		vpc, err = resource.Parse[resource.VpcID](raw)
		if err != nil {
			writeErr(w, r, err)
			return
		}
	}
	acc, err := h.svc.CreateSubnet(r.Context(), c, token, resource.CreateSubnetRequest{Cidr: r.Form.Get("CidrBlock"), VpcID: vpc, Zone: r.Form.Get("AvailabilityZone")})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	sub := acc.Items[0]
	writeXML(w, createSubnetXML{RequestID: requestID(r), Subnet: subnetXML(sub)})
}

func (h *handler) describeInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	q, err := instanceQuery(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeInstances(r.Context(), c, q)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	groups := map[string][]resource.Instance{}
	var order []string
	for _, inst := range page.Items {
		key := inst.ReservationID.String()
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], inst)
	}
	var items []reservationItem
	for _, key := range order {
		items = append(items, reservationItem{ReservationID: key, Instances: instanceItems(groups[key])})
	}
	writeXML(w, describeInstancesXML{RequestID: requestID(r), NextToken: page.NextToken, Reservations: struct {
		Items []reservationItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) describeSubnets(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.SubnetID](r, "SubnetId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeSubnets(r.Context(), c, resource.SubnetQuery{IDs: ids, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []subnetItem
	for _, sub := range page.Items {
		items = append(items, subnetXML(sub))
	}
	writeXML(w, describeSubnetsXML{RequestID: requestID(r), NextToken: page.NextToken, Subnets: struct {
		Items []subnetItem `xml:"item"`
	}{Items: items}})
}

func clientToken(r *http.Request) (resource.ClientToken, error) {
	raw := r.Form.Get("ClientToken")
	if raw == "" {
		return resource.ClientToken{}, resource.Invalid("ClientToken", "ClientToken is required")
	}
	return resource.Parse[resource.ClientToken](raw)
}

func optionalClientToken(r *http.Request) (resource.ClientToken, error) {
	raw := r.Form.Get("ClientToken")
	if raw == "" {
		return resource.ClientToken{}, nil
	}
	return resource.Parse[resource.ClientToken](raw)
}

func exactCount(r *http.Request) (int, error) {
	minRaw, maxRaw := r.Form.Get("MinCount"), r.Form.Get("MaxCount")
	if minRaw == "" && maxRaw == "" {
		return 1, nil
	}
	minC, err1 := strconv.Atoi(minRaw)
	maxC, err2 := strconv.Atoi(maxRaw)
	if err1 != nil || err2 != nil || minC != maxC || minC < 1 {
		return 0, resource.Invalid("MinCount", "MinCount and MaxCount must be equal")
	}
	return minC, nil
}

func tags(r *http.Request) (map[string]string, error) {
	out := map[string]string{}
	for i := 1; i <= 20; i++ {
		n := strconv.Itoa(i)
		k, v := r.Form.Get("Tag."+n+".Key"), r.Form.Get("Tag."+n+".Value")
		if k == "" && v == "" {
			continue
		}
		if k == "" {
			return nil, resource.Invalid("Tag."+n+".Key", "required")
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, nil //nolint:nilnil // A nil map means the request has no tags.
	}
	return out, nil
}

func mergeTags(r *http.Request) (map[string]string, error) {
	base, err := tags(r)
	if err != nil {
		return nil, err
	}
	extra, err := tagSpecifications(r)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return base, nil
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range extra {
		base[k] = v
	}
	return base, nil
}

func tagSpecifications(r *http.Request) (map[string]string, error) {
	out := map[string]string{}
	for i := 1; i <= 5; i++ {
		for j := 1; j <= 20; j++ {
			prefix := "TagSpecification." + strconv.Itoa(i) + ".Tag." + strconv.Itoa(j) + "."
			k, v := r.Form.Get(prefix+"Key"), r.Form.Get(prefix+"Value")
			if k == "" && v == "" {
				continue
			}
			if k == "" {
				return nil, resource.Invalid(prefix+"Key", "required")
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, nil //nolint:nilnil // A nil map means the request has no tags.
	}
	return out, nil
}

func instanceQuery(r *http.Request) (resource.InstanceQuery, error) {
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		return resource.InstanceQuery{}, err
	}
	var states []resource.InstanceState
	for i := 1; i <= 20; i++ {
		name := r.Form.Get("Filter." + strconv.Itoa(i) + ".Name")
		if name == "" {
			continue
		}
		value := r.Form.Get("Filter." + strconv.Itoa(i) + ".Value.1")
		switch name {
		case "instance-id":
			id, err := resource.Parse[resource.InstanceID](value)
			if err != nil {
				return resource.InstanceQuery{}, err
			}
			ids = append(ids, id)
		case "instance-state-name":
			st, ok := resource.ParseInstanceState(value)
			if !ok {
				return resource.InstanceQuery{}, resource.Invalid("Filter", "unknown state")
			}
			states = append(states, st)
		default:
			return resource.InstanceQuery{}, resource.Invalid("Filter", "unsupported")
		}
	}
	page, err := pageForm(r)
	if err != nil {
		return resource.InstanceQuery{}, err
	}
	return resource.InstanceQuery{IDs: ids, States: states, Page: page}, nil
}

func pageForm(r *http.Request) (resource.PageRequest, error) {
	var p resource.PageRequest
	raw := r.Form.Get("MaxResults")
	field := "MaxResults"
	if raw == "" {
		raw = r.Form.Get("maxResults")
		field = "maxResults"
	}
	if raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return p, resource.Invalid(field, "malformed")
		}
		// The AWS CLI sends MaxResults=1000 when the caller gives none. EC2 may
		// return fewer items than asked with a NextToken, so cap at our page max.
		p.Size = min(n, 100)
	}
	p.Token = r.Form.Get("NextToken")
	if p.Token == "" {
		p.Token = r.Form.Get("nextToken")
	}
	return p, nil
}

func indexedIDs[T any, PT interface {
	*T
	encodingText
}](r *http.Request, prefix string) ([]T, error) {
	var out []T
	for i := 1; i <= 100; i++ {
		raw := r.Form.Get(prefix + "." + strconv.Itoa(i))
		if raw == "" {
			continue
		}
		id, err := resource.Parse[T, PT](raw)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

type encodingText interface {
	UnmarshalText([]byte) error
}

func rejectUnknown(r *http.Request, action string) error {
	var allow func(string) bool
	switch action {
	case resource.ActionRunInstances.String():
		allow = allowRun
	case resource.ActionStopInstances.String():
		allow = allowStop
	case resource.ActionCreateSubnet.String():
		allow = allowSubnet
	case resource.ActionCreateVpc.String():
		allow = allowCreateVpc
	case resource.ActionDeleteVpc.String():
		allow = allowDeleteVpc
	case resource.ActionCreateVolume.String():
		allow = allowCreateVolume
	case resource.ActionAttachVolume.String():
		allow = allowAttachVolume
	case resource.ActionDeleteVolume.String():
		allow = allowDeleteVolume
	case resource.ActionCreateSecurityGroup.String():
		allow = allowCreateGroup
	case resource.ActionAuthorizeSecurityGroupIngress.String():
		allow = allowAuthorize
	case resource.ActionStartInstances.String():
		allow = allowStop
	case resource.ActionTerminateInstances.String():
		allow = allowStop
	case resource.ActionCreateKeyPair.String():
		allow = allowCreateKey
	case resource.ActionDeleteKeyPair.String():
		allow = allowDeleteKey
	case resource.ActionDeleteSecurityGroup.String():
		allow = allowDeleteGroup
	case resource.ActionDeleteSubnet.String():
		allow = allowDeleteSubnet
	case resource.ActionAllocateAddress.String():
		allow = allowAllocateAddress
	case resource.ActionReleaseAddress.String():
		allow = allowReleaseAddress
	case resource.ActionCreateSnapshot.String():
		allow = allowCreateSnapshot
	case resource.ActionDeleteSnapshot.String():
		allow = allowDeleteSnapshot
	case "DescribeInstances":
		allow = allowDescribeInstances
	case "DescribeSubnets":
		allow = allowDescribeSubnets
	case "DescribeVpcs":
		allow = allowDescribeVpcs
	case "DescribeVolumes":
		allow = allowDescribeVolumes
	case "DescribeImages":
		allow = allowDescribeImages
	case "DescribeKeyPairs":
		allow = allowDescribeKeyPairs
	case "DescribeSecurityGroups":
		allow = allowDescribeGroups
	case "DescribeAddresses":
		allow = allowDescribeAddresses
	case "DescribeSnapshots":
		allow = allowDescribeSnapshots
	default:
		allow = allowCommon
	}
	for key := range r.Form {
		if !allow(key) {
			return resource.Invalid(key, "unsupported")
		}
	}
	return nil
}

func allowCommon(key string) bool {
	return key == "Action" || key == "Version"
}

func allowRun(key string) bool {
	switch key {
	case "Action", "Version", "ImageId", "InstanceType", "SubnetId", "MinCount", "MaxCount", "ClientToken":
		return true
	default:
		return tagField(key) || tagSpecField(key)
	}
}

func allowStop(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || indexed(key, "InstanceId", 100)
}

func allowSubnet(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "CidrBlock" || key == "VpcId" || key == "AvailabilityZone"
}

func allowCreateVpc(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "CidrBlock" || key == "InstanceTenancy"
}

func allowDeleteVpc(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "VpcId"
}

func allowCreateVolume(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "Size" || key == "AvailabilityZone" || key == "VolumeType" || key == "SnapshotId"
}

func allowAttachVolume(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "VolumeId" || key == "InstanceId" || key == "Device"
}

func allowDeleteVolume(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "VolumeId"
}

func allowCreateGroup(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "GroupName" || key == "GroupDescription" || key == "VpcId"
}

func allowAuthorize(key string) bool {
	if key == "Action" || key == "Version" || key == "ClientToken" || key == "GroupId" || key == "IpProtocol" || key == "FromPort" || key == "ToPort" || key == "CidrIp" {
		return true
	}
	return permissionField(key)
}

func allowCreateKey(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "KeyName"
}

func allowDeleteKey(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "KeyName" || key == "KeyPairId"
}

func allowDeleteGroup(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "GroupId" || key == "GroupName"
}

func allowDeleteSubnet(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "SubnetId"
}

func allowAllocateAddress(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "Domain"
}

func allowReleaseAddress(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "AllocationId"
}

func allowCreateSnapshot(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "VolumeId" || key == "Description"
}

func allowDeleteSnapshot(key string) bool {
	return key == "Action" || key == "Version" || key == "ClientToken" || key == "SnapshotId"
}

func allowDescribeBase(key string) bool {
	switch key {
	case "Action", "Version", "MaxResults", "maxResults", "NextToken", "nextToken", "DryRun", "dryRun":
		return true
	default:
		return filterField(key)
	}
}

func allowDescribeKeyPairs(key string) bool {
	return allowDescribeBase(key) || indexed(key, "KeyName", 100) || indexed(key, "KeyPairId", 100) || key == "IncludePublicKey"
}

func allowDescribeGroups(key string) bool {
	return allowDescribeBase(key) || indexed(key, "GroupId", 100) || indexed(key, "GroupName", 100)
}

func allowDescribeAddresses(key string) bool {
	return allowDescribeBase(key) || indexed(key, "AllocationId", 100) || indexed(key, "PublicIp", 100)
}

func allowDescribeSnapshots(key string) bool {
	return allowDescribeBase(key) || indexed(key, "SnapshotId", 100) || indexed(key, "Owner", 100) || indexed(key, "OwnerId", 100) || indexed(key, "RestorableBy", 100)
}

func allowDescribeVpcs(key string) bool {
	return allowDescribeBase(key) || indexed(key, "VpcId", 100)
}

func allowDescribeVolumes(key string) bool {
	return allowDescribeBase(key) || indexed(key, "VolumeId", 100)
}

func allowDescribeImages(key string) bool {
	return allowDescribeBase(key) || indexed(key, "ImageId", 100) || indexed(key, "Owner", 100) || indexed(key, "OwnerId", 100) || indexed(key, "ExecutableBy", 100) || key == "IncludeDeprecated" || key == "IncludeDisabled"
}

func allowDescribeInstances(key string) bool {
	return allowDescribeBase(key) || indexed(key, "InstanceId", 100)
}

func allowDescribeSubnets(key string) bool {
	return allowDescribeBase(key) || indexed(key, "SubnetId", 100)
}

func rejectDryRun(r *http.Request) error {
	raw := r.Form.Get("DryRun")
	if raw == "" {
		raw = r.Form.Get("dryRun")
	}
	switch raw {
	case "", "false":
		return nil
	case "true":
		return resource.Invalid("DryRun", "unsupported")
	default:
		return resource.Invalid("DryRun", "malformed")
	}
}

func rejectPlainFilters(r *http.Request) error {
	for i := 1; i <= 20; i++ {
		if r.Form.Get("Filter."+strconv.Itoa(i)+".Name") != "" {
			return resource.Invalid("Filter", "unsupported")
		}
	}
	return nil
}

func optionalBool(r *http.Request, key string) error {
	switch r.Form.Get(key) {
	case "", "true", "false":
		return nil
	default:
		return resource.Invalid(key, "malformed")
	}
}

// ownerSelectsCaller reports whether Owner or OwnerId keeps this account.
// boto3 sends OwnerIds as Owner.N. An empty list keeps the caller's rows.
func ownerSelectsCaller(r *http.Request, account resource.AccountID) bool {
	owners := append(indexedStrings(r, "Owner"), indexedStrings(r, "OwnerId")...)
	return selectsCaller(owners, account)
}

func selectsCaller(values []string, account resource.AccountID) bool {
	if len(values) == 0 {
		return true
	}
	self := account.String()
	for _, value := range values {
		if value == "self" || value == self {
			return true
		}
	}
	return false
}

func tagSpecField(key string) bool {
	rest, ok := strings.CutPrefix(key, "TagSpecification.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || !inRange(n, 5) {
		return false
	}
	if field == "ResourceType" {
		return true
	}
	tagRest, ok := strings.CutPrefix(field, "Tag.")
	if !ok {
		return false
	}
	m, leaf, ok := strings.Cut(tagRest, ".")
	if !ok || !inRange(m, 20) {
		return false
	}
	return leaf == "Key" || leaf == "Value"
}

func permissionField(key string) bool {
	rest, ok := strings.CutPrefix(key, "IpPermissions.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || n != "1" {
		return false
	}
	switch field {
	case "IpProtocol", "FromPort", "ToPort", "CidrIp":
		return true
	default:
	}
	rangeRest, ok := strings.CutPrefix(field, "IpRanges.")
	if !ok {
		return false
	}
	m, leaf, ok := strings.Cut(rangeRest, ".")
	return ok && m == "1" && leaf == "CidrIp"
}

func tagField(key string) bool {
	rest, ok := strings.CutPrefix(key, "Tag.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || (field != "Key" && field != "Value") {
		return false
	}
	return inRange(n, 20)
}

func filterField(key string) bool {
	rest, ok := strings.CutPrefix(key, "Filter.")
	if !ok {
		return false
	}
	n, field, ok := strings.Cut(rest, ".")
	if !ok || !inRange(n, 20) {
		return false
	}
	return field == "Name" || field == "Value.1"
}

func indexed(key, prefix string, max int) bool {
	rest, ok := strings.CutPrefix(key, prefix+".")
	if !ok || strings.Contains(rest, ".") {
		return false
	}
	return inRange(rest, max)
}

func inRange(raw string, max int) bool {
	n, err := strconv.Atoi(raw)
	return err == nil && n >= 1 && n <= max
}

func requestID(r *http.Request) string { return r.Header.Get("X-Request-Id") }

func writeXML(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(xml.Header))
	if err == nil {
		err = xml.NewEncoder(w).Encode(v)
	}
	server.RecordFailure(w, err)
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	e := resource.AsError(err)
	if statusOf(e.Code) >= http.StatusInternalServerError {
		server.RecordFailure(w, err)
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(statusOf(e.Code))
	_, werr := w.Write([]byte(xml.Header))
	if werr == nil {
		werr = xml.NewEncoder(w).Encode(errorXML{
			Code: ec2Code(e), Message: e.Message, RequestID: requestID(r),
		})
	}
	server.RecordFailure(w, werr)
}

func statusOf(c resource.Code) int {
	switch c {
	case resource.CodeUnauthenticated:
		return http.StatusUnauthorized
	case resource.CodePermissionDenied:
		return http.StatusForbidden
	case resource.CodeUnimplemented:
		return http.StatusNotImplemented
	case resource.CodeUnavailable:
		return http.StatusServiceUnavailable
	case resource.CodeInternal, resource.CodeUnspecified:
		return http.StatusInternalServerError
	case resource.CodeInvalidArgument, resource.CodeNotFound, resource.CodeAlreadyExists,
		resource.CodeConflict, resource.CodeIdempotencyMismatch, resource.CodeResourceExhausted,
		resource.CodePayloadTooLarge:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func ec2Code(e *resource.Error) string {
	switch e.Code {
	case resource.CodeNotFound:
		return notFoundCode(e.Kind)
	case resource.CodeInvalidArgument:
		return "InvalidParameterValue"
	case resource.CodeAlreadyExists:
		return alreadyExistsCode(e.Kind)
	case resource.CodeConflict:
		return conflictCode(e.Kind)
	case resource.CodeIdempotencyMismatch:
		return "IdempotentParameterMismatch"
	case resource.CodeUnauthenticated:
		return "AuthFailure"
	case resource.CodePermissionDenied:
		return "UnauthorizedOperation"
	case resource.CodeResourceExhausted:
		return "RequestLimitExceeded"
	case resource.CodePayloadTooLarge:
		return "InvalidParameterValue"
	case resource.CodeUnavailable:
		return "Unavailable"
	case resource.CodeUnimplemented:
		return "InvalidAction"
	case resource.CodeInternal, resource.CodeUnspecified:
		return "InternalError"
	default:
		return "InternalError"
	}
}

func notFoundCode(k resource.Kind) string {
	switch k {
	case resource.KindInstance:
		return "InvalidInstanceID.NotFound"
	case resource.KindSubnet:
		return "InvalidSubnetID.NotFound"
	case resource.KindImage:
		return "InvalidAMIID.NotFound"
	case resource.KindVpc:
		return "InvalidVpcID.NotFound"
	case resource.KindVolume:
		return "InvalidVolume.NotFound"
	case resource.KindSecurityGroup:
		return "InvalidGroup.NotFound"
	case resource.KindKeyPair:
		return "InvalidKeyPair.NotFound"
	case resource.KindAddress:
		return "InvalidAllocationID.NotFound"
	case resource.KindSnapshot:
		return "InvalidSnapshot.NotFound"
	case resource.KindReservation, resource.KindBucket, resource.KindObject, resource.KindOperation, resource.KindUnspecified:
		return "InvalidParameterValue"
	default:
		return "InvalidParameterValue"
	}
}

func conflictCode(k resource.Kind) string {
	switch k {
	case resource.KindVolume:
		return "IncorrectState"
	case resource.KindVpc, resource.KindSubnet:
		return "DependencyViolation"
	case resource.KindInstance, resource.KindImage, resource.KindReservation,
		resource.KindBucket, resource.KindObject, resource.KindOperation, resource.KindSecurityGroup,
		resource.KindKeyPair, resource.KindAddress, resource.KindSnapshot, resource.KindUnspecified:
		return "IncorrectInstanceState"
	default:
		return "IncorrectInstanceState"
	}
}

func alreadyExistsCode(k resource.Kind) string {
	switch k {
	case resource.KindSecurityGroup:
		return "InvalidGroup.Duplicate"
	case resource.KindKeyPair:
		return "InvalidKeyPair.Duplicate"
	case resource.KindInstance, resource.KindImage, resource.KindReservation, resource.KindSubnet,
		resource.KindBucket, resource.KindObject, resource.KindOperation, resource.KindVpc,
		resource.KindVolume, resource.KindAddress, resource.KindSnapshot, resource.KindUnspecified:
		return "InvalidParameterValue"
	default:
		return "InvalidParameterValue"
	}
}
