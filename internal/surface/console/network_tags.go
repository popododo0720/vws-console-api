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

// untagBody is {"tags":[{"key":"Name"},{"key":"env","value":"dev"}]}. A
// selector with no value deletes the key whatever its value; with a value,
// only that value. No tags deletes every user tag, as in EC2 DeleteTags.
type untagBody struct {
	Tags []resource.TagSelector `json:"tags"`
}

// deleteTags deletes tags from one instance.
func (h *handler) deleteTags(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body untagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.DeleteTagsRequest{IDs: []resource.InstanceID{id}, Tags: body.Tags}
	acc, err := h.svc.DeleteTags(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

// untagVpc deletes tags from one VPC.
func (h *handler) untagVpc(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VpcID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body untagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.UntagVpcsRequest{IDs: []resource.VpcID{id}, Tags: body.Tags}
	acc, err := h.svc.UntagVpcs(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

// untagSubnet deletes tags from one subnet.
func (h *handler) untagSubnet(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.SubnetID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body untagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.UntagSubnetsRequest{IDs: []resource.SubnetID{id}, Tags: body.Tags}
	acc, err := h.svc.UntagSubnets(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}
