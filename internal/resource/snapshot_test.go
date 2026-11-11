package resource

import (
	"strings"
	"testing"
)

func TestCreateSnapshotTagsNormalize(t *testing.T) {
	id, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for name, tags := range map[string]map[string]string{
		"reserved": {"aws:owner": "x"},
		"case":     {"AWS:owner": "x"},
		"key":      {strings.Repeat("k", 129): "x"},
		"value":    {"k": strings.Repeat("v", 257)},
		"control":  {"k": "x\n"},
	} {
		if _, err := (CreateSnapshotRequest{VolumeID: id, Tags: tags}).Normalize(); CodeOf(err) != CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	tags := map[string]string{"Name": "", "Owner Team": "Platform"}
	got, err := (CreateSnapshotRequest{VolumeID: id, Tags: tags}).Normalize()
	if err != nil || len(got.Tags) != 2 || got.Tags["Owner Team"] != "Platform" {
		t.Fatalf("valid tags: %+v %v", got, err)
	}
}
