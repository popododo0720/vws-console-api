package console

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// tagBody is {"tags":{"Name":"web"}}. Tags not named stay.
type tagBody struct {
	Tags map[string]string `json:"tags"`
}

// tagVpc adds or overwrites tags on one VPC.
func (h *handler) tagVpc(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VpcID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body tagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.TagVpcs(r.Context(), c, token, resource.TagVpcsRequest{IDs: []resource.VpcID{id}, Tags: body.Tags})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

// tagSubnet adds or overwrites tags on one subnet.
func (h *handler) tagSubnet(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SubnetID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body tagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.TagSubnets(r.Context(), c, token, resource.TagSubnetsRequest{IDs: []resource.SubnetID{id}, Tags: body.Tags})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}
