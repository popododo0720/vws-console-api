package resource

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOptionalResultIDsKeepWireBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		wire  string
	}{
		{"volume", Volume{}, `{"volumeId":"","ownerId":"","size":0,"availabilityZone":"",` +
			`"volumeType":"","state":"","instanceId":"","createTime":"0001-01-01T00:00:00Z"}`},
		{"address", Address{}, `{"allocationId":"","ownerId":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tc.wire {
				t.Fatalf("wire changed: %s", data)
			}
		})
	}
}

func TestVolumeOptionalInstanceIDJSON(t *testing.T) {
	for _, input := range []string{`{"instanceId":""}`, `{}`} {
		var got Volume
		if err := json.Unmarshal([]byte(input), &got); err != nil {
			t.Fatal(err)
		}
		if !got.InstanceID.IsZero() {
			t.Fatal("expected unbound volume")
		}
	}
	for _, input := range []string{`{"instanceId":"bad"}`, `{"instanceId":null}`, `{"instanceId":1}`} {
		var got Volume
		if err := json.Unmarshal([]byte(input), &got); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	var required VolumeAttachment
	if err := json.Unmarshal([]byte(`{"instanceId":""}`), &required); err == nil {
		t.Fatal("attachment accepted missing required instance")
	}
	if _, err := Parse[InstanceID](""); err == nil {
		t.Fatal("Parse accepted empty instance ID")
	}
	id, err := Parse[InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	want := Volume{InstanceID: id}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	// Decode just the optional field: required volume and owner IDs stay strict.
	var got Volume
	if err := json.Unmarshal([]byte(`{"instanceId":"`+id.String()+`"}`), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed: %+v (wire %s)", got, data)
	}
}
