package console

import (
	"bytes"
	"encoding/json"
	"errors"
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

// errAmbiguousUntag refuses a JSON null where omission means something:
// a null body or "tags" would read as delete every tag, and a null "value"
// as delete whatever the value.
var errAmbiguousUntag = errors.New("null is not a tag selector")

// UnmarshalJSON decodes untagBody strictly: no null in place of the body,
// "tags", an item, "key" or "value", and no field other than those.
func (b *untagBody) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err //nolint:wrapcheck // decode reports any error as malformed json
	}
	if fields == nil {
		return errAmbiguousUntag
	}
	for name := range fields {
		if name != "tags" {
			return errors.New("unknown field " + name)
		}
	}
	raw, ok := fields["tags"]
	if !ok {
		return nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return err //nolint:wrapcheck // decode reports any error as malformed json
	}
	if items == nil {
		return errAmbiguousUntag
	}
	b.Tags = make([]resource.TagSelector, 0, len(items))
	for _, item := range items {
		sel, err := untagSelector(item)
		if err != nil {
			return err
		}
		b.Tags = append(b.Tags, sel)
	}
	return nil
}

func untagSelector(item map[string]json.RawMessage) (resource.TagSelector, error) {
	if item == nil {
		return resource.TagSelector{}, errAmbiguousUntag
	}
	var sel resource.TagSelector
	for name, raw := range item {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return resource.TagSelector{}, errAmbiguousUntag
		}
		switch name {
		case "key":
			if err := json.Unmarshal(raw, &sel.Key); err != nil {
				return resource.TagSelector{}, err //nolint:wrapcheck // decode reports any error as malformed json
			}
		case "value":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return resource.TagSelector{}, err //nolint:wrapcheck // decode reports any error as malformed json
			}
			sel.Value = &v
		default:
			return resource.TagSelector{}, errors.New("unknown field " + name)
		}
	}
	return sel, nil
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

// tagVolume adds or overwrites tags on one volume.
func (h *handler) tagVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body tagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.TagVolumesRequest{IDs: []resource.VolumeID{id}, Tags: body.Tags}
	acc, err := h.svc.TagVolumes(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}

func (h *handler) untagVolume(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.VolumeID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	var body untagBody
	if err := decode(w, r, &body); err != nil {
		writeErr(w, r, err)
		return
	}
	req := resource.UntagVolumesRequest{IDs: []resource.VolumeID{id}, Tags: body.Tags}
	acc, err := h.svc.UntagVolumes(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeAccepted(w, acc)
}
