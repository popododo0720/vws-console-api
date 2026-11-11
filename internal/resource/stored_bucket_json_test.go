package resource

import (
	"encoding/json"
	"testing"
)

func TestStoredBucketJSONDoesNotRelaxCreatePolicy(t *testing.T) {
	for _, name := range []string{"ab", "xn--bucket", "edge-bucket-an"} {
		if _, err := Parse[BucketName](name); err == nil {
			t.Fatalf("create accepted %s", name)
		}
		data, err := json.Marshal(name)
		if err != nil {
			t.Fatal(err)
		}
		var got BucketName
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.String() != name {
			t.Fatalf("stored name changed: %s", got)
		}
	}
	for _, input := range []string{`null`, `""`, `"BAD"`, `"a..b"`, `1`} {
		var got BucketName
		if err := json.Unmarshal([]byte(input), &got); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
