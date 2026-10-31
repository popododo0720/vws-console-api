package console

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestCreateBucketRefusesReservedNames(t *testing.T) {
	e := newLoginEnv(t)
	bearer := map[string]string{"Authorization": "Bearer tok", "Origin": ""}
	for _, name := range []string{"xn--bucket", "edge-bucket--ol-s3", "edge-bucket-an"} {
		t.Run(name, func(t *testing.T) {
			rec := e.do(t, http.MethodPut, "/api/v1/buckets/"+name, "", bearer)
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest || body.Error.Code != "InvalidArgument" {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
}
