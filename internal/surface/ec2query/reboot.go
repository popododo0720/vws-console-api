package ec2query

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type rebootXML struct {
	XMLName   struct{} `xml:"RebootInstancesResponse"`
	RequestID string   `xml:"requestId"`
	Return    bool     `xml:"return"`
}

// rebootInstances answers as EC2 does, true once the reboot is accepted.
// EC2 RebootInstances takes no ClientToken, so the kernel mints one.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RebootInstances.html
func (h *handler) rebootInstances(w http.ResponseWriter, r *http.Request, c resource.Caller) {
	ids, err := indexedIDs[resource.InstanceID](r, "InstanceId")
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if _, err := h.svc.RebootInstances(
		r.Context(), c, resource.ClientToken{}, resource.RebootInstancesRequest{IDs: ids},
	); err != nil {
		writeErr(w, r, err)
		return
	}
	writeXML(w, rebootXML{RequestID: requestID(r), Return: true})
}

func allowReboot(key string) bool {
	return key == "Action" || key == "Version" || indexed(key, "InstanceId", 100)
}
