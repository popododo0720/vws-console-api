package console

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (h *handler) deleteKeyPair(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.KeyPairID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteKeyPair(r.Context(), c, token, resource.DeleteKeyPairRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) listKeyPairs(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeKeyPairs(r.Context(), c, resource.KeyPairQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) deleteSecurityGroup(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SecurityGroupID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteSecurityGroup(r.Context(), c, token, resource.DeleteSecurityGroupRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) listSecurityGroups(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeSecurityGroups(r.Context(), c, resource.SecurityGroupQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) deleteSubnet(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SubnetID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteSubnet(r.Context(), c, token, resource.DeleteSubnetRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) allocateAddress(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.AllocateAddressRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.AllocateAddress(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) releaseAddress(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.AddressID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.ReleaseAddress(r.Context(), c, token, resource.ReleaseAddressRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) associateAddress(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.AssociateAddressRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	id, err := resource.Parse[resource.AddressID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req.ID = id
	acc, err := h.svc.AssociateAddress(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) disassociateAddress(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.AddressID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DisassociateAddress(r.Context(), c, token, resource.DisassociateAddressRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) listAddresses(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeAddresses(r.Context(), c, resource.AddressQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) createSnapshot(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req resource.CreateSnapshotRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.CreateSnapshot(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SnapshotID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.DeleteSnapshot(r.Context(), c, token, resource.DeleteSnapshotRequest{ID: id})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, r, acc)
}

func (h *handler) listSnapshots(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page, err := pageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := h.svc.DescribeSnapshots(r.Context(), c, resource.SnapshotQuery{Page: page})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
