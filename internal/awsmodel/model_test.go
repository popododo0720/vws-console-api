package awsmodel

import (
	"bytes"
	"compress/gzip"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestLoadEC2ChecksDigestAndGzip(t *testing.T) {
	raw, err := files.ReadFile("ec2-2016-11-15.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	z.Close()
	data = append(data, '\n')
	var altered bytes.Buffer
	gz := gzip.NewWriter(&altered)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, message string
		raw           []byte
	}{
		{"digest mismatch", "digest mismatch", altered.Bytes()},
		{"corrupt header", "open EC2 model gzip", []byte("broken gzip")},
		{"truncated stream", "decompress EC2 model", raw[:len(raw)/2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.raw); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("load: %v, want %s", err, tc.message)
			}
		})
	}
}

func TestEC2Operations(t *testing.T) {
	m, err := LoadEC2()
	if err != nil {
		t.Fatal(err)
	}
	ops := m.Operations()
	if len(ops) != 811 || !slices.IsSorted(ops) || m.Metadata.APIVersion != "2016-11-15" {
		t.Fatalf("model: version %s, %d operations, sorted %t",
			m.Metadata.APIVersion, len(ops), slices.IsSorted(ops))
	}
}

func TestQueryKeysFollowEC2Serialization(t *testing.T) {
	m, err := LoadEC2()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action string
		want   []Key
	}{
		{"DescribeVolumes", []Key{
			{"DryRun", false, "boolean"},
			{"Filter.N.Name", false, "string"},
			{"Filter.N.Value.N", false, "string"},
			{"IncludeManagedResources", false, "boolean"},
			{"MaxResults", false, "integer"},
			{"NextToken", false, "string"},
			{"VolumeId.N", false, "string"},
		}},
		{"RebootInstances", []Key{{"DryRun", false, "boolean"}, {"InstanceId.N", true, "string"}}},
		{"CreateTags", []Key{
			{"DryRun", false, "boolean"},
			{"ResourceId.N", true, "string"},
			{"Tag.N.Key", true, "string"},
			{"Tag.N.Value", true, "string"},
		}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			keys, err := m.QueryKeys(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(keys, tc.want) {
				t.Fatalf("keys: %v, want %v", keys, tc.want)
			}
		})
	}
	keys, err := m.QueryKeys("RunInstances")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"BlockDeviceMapping.N.Ebs.VolumeSize", "TagSpecification.N.Tag.N.Key"} {
		if !slices.ContainsFunc(keys, func(k Key) bool { return k.Path == path }) {
			t.Errorf("RunInstances missing %s", path)
		}
	}
}

func TestQueryKeysRejectRecursiveAndMissingShapes(t *testing.T) {
	for _, tc := range []struct {
		name, child, message string
	}{
		{"recursive", "Root", "recursive input shape"},
		{"missing", "Absent", "missing shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{
				OperationsByName: map[string]operation{"Cycle": {Input: reference{Shape: "Root"}}},
				Shapes: map[string]shape{"Root": {
					Type: "structure", Members: map[string]reference{"Child": {Shape: tc.child}},
				}},
			}
			if _, err := m.QueryKeys("Cycle"); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("QueryKeys: %v, want %s", err, tc.message)
			}
		})
	}
}
