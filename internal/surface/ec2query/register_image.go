package ec2query

import (
	"net/http"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// The one block device mapping RegisterImage takes: the root, from a snapshot.
const (
	registerDevice      = "BlockDeviceMapping.1.DeviceName"
	registerSnapshot    = "BlockDeviceMapping.1.Ebs.SnapshotId"
	registerDeleteOnEnd = "BlockDeviceMapping.1.Ebs.DeleteOnTermination"
)

type registerImageXML struct {
	XMLName   struct{} `xml:"RegisterImageResponse"`
	RequestID string   `xml:"requestId"`
	ImageID   string   `xml:"imageId"`
}

func (h *handler) registerImage(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	token, err := optionalClientToken(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	req, err := registerImageRequest(r)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	acc, err := h.svc.RegisterImage(r.Context(), c, token, req)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, registerImageXML{RequestID: requestID(r), ImageID: acc.Items[0].ID.String()})
}

// registerImageRequest reads an image whose root is a copy of one snapshot.
// A missing parameter is named as the query spells it. Architecture,
// VirtualizationType, EnaSupport and the root's DeleteOnTermination may only
// state what every VWS image is (x86_64, hvm, ENA, a root deleted with its
// instance); any other value is UnsupportedOperation rather than dropped.
func registerImageRequest(r *http.Request) (resource.RegisterImageRequest, error) {
	name := r.Form.Get("Name")
	if name == "" {
		return resource.RegisterImageRequest{}, missing("Name")
	}
	for _, fixed := range []struct{ key, value, reason string }{
		{"Architecture", "x86_64", "VWS images are x86_64"},
		{"VirtualizationType", "hvm", "VWS images are hvm"},
	} {
		if v := r.Form.Get(fixed.key); r.Form.Has(fixed.key) && v != fixed.value {
			return resource.RegisterImageRequest{}, resource.Unsupported(fixed.key,
				fixed.key+" "+v+" is not supported: "+fixed.reason+".")
		}
	}
	for _, flag := range []struct{ key, reason string }{
		{"EnaSupport", "every VWS image has ENA support"},
		{registerDeleteOnEnd, "a VWS image's root volume is deleted with its instance"},
	} {
		if err := onlyTrue(r, flag.key, flag.reason); err != nil {
			return resource.RegisterImageRequest{}, err
		}
	}
	device := r.Form.Get(registerDevice)
	if device == "" {
		return resource.RegisterImageRequest{}, missing(registerDevice)
	}
	if device != resource.RootDeviceName && device != strings.TrimPrefix(resource.RootDeviceName, "/dev/") {
		return resource.RegisterImageRequest{}, resource.Unsupported(registerDevice,
			registerDevice+" "+device+" is not supported: a VWS image boots from "+resource.RootDeviceName+".")
	}
	if root := r.Form.Get("RootDeviceName"); r.Form.Has("RootDeviceName") && root != device {
		return resource.RegisterImageRequest{}, resource.Invalid("blockDeviceMapping",
			"The root device name "+root+" is not the device of a block device mapping.")
	}
	raw := r.Form.Get(registerSnapshot)
	if raw == "" {
		return resource.RegisterImageRequest{}, missing(registerSnapshot)
	}
	snap, err := resource.Parse[resource.SnapshotID](raw)
	if err != nil {
		return resource.RegisterImageRequest{}, err
	}
	return resource.RegisterImageRequest{Name: name, Description: r.Form.Get("Description"), SnapshotID: snap}, nil
}

func missing(key string) error {
	return resource.MissingParameter(key, "The request must contain the parameter "+key)
}

func onlyTrue(r *http.Request, key, reason string) error {
	if !r.Form.Has(key) {
		return nil
	}
	switch v := r.Form.Get(key); {
	case strings.EqualFold(v, "true"):
		return nil
	case strings.EqualFold(v, "false"):
		return resource.Unsupported(key, key+" false is not supported: "+reason+".")
	default:
		return resource.Invalid(key, "Value ("+v+") for parameter "+key+" is invalid.")
	}
}
