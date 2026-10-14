package console

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) createVpc(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateVpcRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateVpc(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) deleteVpc(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VpcID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteVpc(r.Context(), c, token, resource.DeleteVpcRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) listVpcs(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeVpcs(r.Context(), c, resource.VpcQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) createVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateVolumeRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateVolume(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) attachVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body struct {
		InstanceID resource.InstanceID `json:"instanceId"`
		Device     string              `json:"device"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AttachVolume(r.Context(), c, token, resource.AttachVolumeRequest{
		VolumeID: id, InstanceID: body.InstanceID, Device: body.Device,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) deleteVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteVolume(r.Context(), c, token, resource.DeleteVolumeRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) listVolumes(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeVolumes(r.Context(), c, resource.VolumeQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) listImages(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeImages(r.Context(), c, resource.ImageQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) createSecurityGroup(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateSecurityGroupRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateSecurityGroup(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) authorizeIngress(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SecurityGroupID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body struct {
		Rule resource.IngressRule `json:"ipPermissions"`
	}
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AuthorizeSecurityGroupIngress(r.Context(), c, token, resource.AuthorizeSecurityGroupIngressRequest{
		ID: id, Rule: body.Rule,
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) startInstance(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.StartInstances(r.Context(), c, token, resource.StartInstancesRequest{IDs: []resource.InstanceID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) terminateInstance(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.TerminateInstances(r.Context(), c, token, resource.TerminateInstancesRequest{IDs: []resource.InstanceID{id}})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) createKeyPair(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateKeyPairRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateKeyPair(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

// modifyVolume grows a volume. The body is {"size": N}.
func (h *handler) modifyVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var req resource.ModifyVolumeRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	req.ID = id
	acc, err := h.svc.ModifyVolume(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

// createTags adds or overwrites tags on one instance. The body is
// {"tags":{"Name":"web"}}. Tags not named stay.
func (h *handler) createTags(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var req resource.CreateTagsRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	req.IDs = []resource.InstanceID{id}
	acc, err := h.svc.CreateTags(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}
