package console

import (
	"net/http"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func writeInventory[T any](w http.ResponseWriter, page resource.Page[T]) {
	partial := make([]resource.Partial, len(page.Partial))
	for i, failure := range page.Partial {
		if failure.Error != "region timed out" {
			failure.Error = "region unavailable"
		}
		partial[i] = failure
	}
	page.Partial = partial
	if page.Stale {
		w.Header().Set("X-Vws-Stale", "true")
	}
	writeJSON(w, http.StatusOK, page)
}
