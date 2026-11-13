package regionapi

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// WriteNotReady carries only classified diagnostics across the region boundary.
func WriteNotReady(w http.ResponseWriter, err error) {
	message := resource.RegionFailureMessage(err)
	if message == "" {
		message = "not ready"
	}
	writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: message})
}
