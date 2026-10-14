package ec2query

import (
	"encoding/base64"
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) deleteKeyPair(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.DeleteKeyPairRequest{Name: r.Form.Get("KeyName")}
	if raw := r.Form.Get("KeyPairId"); raw != "" {
		id, err := resource.Parse[resource.KeyPairID](raw)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		req.ID = id
	}
	if _, err := h.svc.DeleteKeyPair(r.Context(), c, token, req); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteKeyXML{RequestID: requestID(r), Return: true})
}

func (h *handler) describeKeyPairs(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	if err := optionalBool(r, "IncludePublicKey"); err != nil {
		writeErr(w, r, err)
		return
	}
	ids, err := indexedIDs[resource.KeyPairID](r, "KeyPairId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeKeyPairs(r.Context(), c, resource.KeyPairQuery{
		IDs: ids, Names: indexedStrings(r, "KeyName"), Page: pageReq,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []keyItem
	for _, key := range page.Items {
		items = append(items, keyXML(key))
	}
	writeXML(w, describeKeysXML{RequestID: requestID(r), NextToken: page.NextToken, Keys: struct {
		Items []keyItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) deleteSecurityGroup(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.DeleteSecurityGroupRequest{Name: r.Form.Get("GroupName")}
	if raw := r.Form.Get("GroupId"); raw != "" {
		id, err := resource.Parse[resource.SecurityGroupID](raw)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		req.ID = id
	}
	if _, err := h.svc.DeleteSecurityGroup(r.Context(), c, token, req); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteGroupXML{RequestID: requestID(r), Return: true})
}

func (h *handler) describeSecurityGroups(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.SecurityGroupID](r, "GroupId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeSecurityGroups(r.Context(), c, resource.SecurityGroupQuery{
		IDs: ids, Names: indexedStrings(r, "GroupName"), Page: pageReq,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []groupItem
	for _, group := range page.Items {
		items = append(items, groupXML(group))
	}
	writeXML(w, describeGroupsXML{RequestID: requestID(r), NextToken: page.NextToken, Groups: struct {
		Items []groupItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) deleteSubnet(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.SubnetID](r.Form.Get("SubnetId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.DeleteSubnet(r.Context(), c, token, resource.DeleteSubnetRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteSubnetXML{RequestID: requestID(r), Return: true})
}

func (h *handler) allocateAddress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AllocateAddress(r.Context(), c, token, resource.AllocateAddressRequest{Domain: r.Form.Get("Domain")})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, allocateAddressXML{
		RequestID: requestID(r), AllocationID: acc.Items[0].ID.String(),
		PublicIP: acc.Items[0].PublicIP, Domain: acc.Items[0].Domain,
	})
}

func (h *handler) releaseAddress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.AddressID](r.Form.Get("AllocationId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.ReleaseAddress(r.Context(), c, token, resource.ReleaseAddressRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, releaseAddressXML{RequestID: requestID(r), Return: true})
}

func (h *handler) associateAddress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.AddressID](r.Form.Get("AllocationId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	inst, err := resource.Parse[resource.InstanceID](r.Form.Get("InstanceId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AssociateAddress(r.Context(), c, token, resource.AssociateAddressRequest{ID: id, InstanceID: inst})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, associateAddressXML{RequestID: requestID(r), Return: true, AssociationID: resource.AssociationID(acc.Items[0].ID)})
}

func (h *handler) disassociateAddress(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.ParseAssociationID(r.Form.Get("AssociationId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.DisassociateAddress(r.Context(), c, token, resource.DisassociateAddressRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, disassociateAddressXML{RequestID: requestID(r), Return: true})
}

func (h *handler) describeAddresses(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.AddressID](r, "AllocationId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeAddresses(r.Context(), c, resource.AddressQuery{
		IDs: ids, PublicIPs: indexedStrings(r, "PublicIp"), Page: pageReq,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []addressItem
	for _, addr := range page.Items {
		items = append(items, addressXML(addr))
	}
	writeXML(w, describeAddressesXML{RequestID: requestID(r), NextToken: page.NextToken, Addresses: struct {
		Items []addressItem `xml:"item"`
	}{Items: items}})
}

func (h *handler) createSnapshot(w http.ResponseWriter, r *http.Request, c resource.Caller) {
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
	acc, err := h.svc.CreateSnapshot(r.Context(), c, token, resource.CreateSnapshotRequest{
		VolumeID: vol, Description: r.Form.Get("Description"),
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, snapshotCreatedXML(requestID(r), acc.Items[0]))
}

func (h *handler) deleteSnapshot(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.SnapshotID](r.Form.Get("SnapshotId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.DeleteSnapshot(r.Context(), c, token, resource.DeleteSnapshotRequest{ID: id}); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, deleteSnapshotXML{RequestID: requestID(r), Return: true})
}

func (h *handler) describeSnapshots(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	if !ownerSelectsCaller(r, c.Account) || !selectsCaller(indexedStrings(r, "RestorableBy"), c.Account) {
		writeXML(w, describeSnapshotsXML{RequestID: requestID(r)})
		return
	}
	ids, err := indexedIDs[resource.SnapshotID](r, "SnapshotId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	pageReq, err := pageForm(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeSnapshots(r.Context(), c, resource.SnapshotQuery{IDs: ids, Page: pageReq})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var items []snapshotItem
	for _, snap := range page.Items {
		items = append(items, snapshotXML(snap))
	}
	writeXML(w, describeSnapshotsXML{RequestID: requestID(r), NextToken: page.NextToken, Snapshots: struct {
		Items []snapshotItem `xml:"item"`
	}{Items: items}})
}

func indexedStrings(r *http.Request, prefix string) []string {
	var out []string
	for i := 1; i <= 100; i++ {
		raw := r.Form.Get(prefix + "." + itoa(i))
		if raw == "" {
			continue
		}
		out = append(out, raw)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// importKeyPair stores a public key the caller made. EC2 has no ClientToken
// here, so a retry of the same key and name is a duplicate.
func (h *handler) importKeyPair(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	public, err := blob(r, "PublicKeyMaterial")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if public == "" {
		writeErr(w, r, resource.Invalid("PublicKeyMaterial", "required"))
		return
	}
	acc, err := h.svc.CreateKeyPair(r.Context(), c, resource.ClientToken{}, resource.CreateKeyPairRequest{
		Name: r.Form.Get("KeyName"), PublicKey: public,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	key := acc.Items[0]
	writeXML(w, importKeyXML{
		RequestID: requestID(r), KeyFingerprint: key.Fingerprint, KeyName: key.Name, KeyPairID: key.ID.String(),
	})
}

// describeInstanceAttribute serves the userData attribute, base64 encoded as
// EC2 returns it.
func (h *handler) describeInstanceAttribute(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	if attr := r.Form.Get("Attribute"); attr != "userData" {
		writeErr(w, r, resource.Invalid("Attribute", "only userData is supported"))
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.Form.Get("InstanceId"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	page, err := h.svc.DescribeInstances(r.Context(), c, resource.InstanceQuery{
		IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if len(page.Items) == 0 {
		writeErr(w, r, resource.NotFound(resource.KindInstance, id.String()))
		return
	}
	out := instanceAttributeXML{RequestID: requestID(r), InstanceID: id.String()}
	if ud := page.Items[0].UserData; ud != "" {
		out.UserData.Value = base64.StdEncoding.EncodeToString([]byte(ud))
	}
	writeXML(w, out)
}
