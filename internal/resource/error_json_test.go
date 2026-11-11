package resource

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestErrorJSONRoundTrip(t *testing.T) {
	for _, code := range append(Codes(), CodeUnspecified) {
		want := &Error{Code: code, Kind: KindInstance, ID: "i-0123456789abcdef0", Field: "id", Message: "failed"}
		data, err := json.Marshal(want.WithCause(errors.New("secret")))
		if err != nil {
			t.Fatal(err)
		}
		got := Error{cause: errors.New("old cause")}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(&got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
	for _, input := range []string{`null`, `{}`, `{"code":"Future"}`, `{"code":"NotFound","kind":"future"}`} {
		var got Error
		if err := json.Unmarshal([]byte(input), &got); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestInsufficientInstanceCapacityJSON(t *testing.T) {
	want := InsufficientInstanceCapacity()
	if want.Code != CodeUnavailable || want.Kind != KindInstance || !IsInsufficientInstanceCapacity(want) ||
		IsInsufficientInstanceCapacity(nil) || IsInsufficientInstanceCapacity(&Error{Code: CodeUnavailable}) {
		t.Fatalf("capacity classification: %+v", want)
	}
	data, err := json.Marshal(want.WithCause(errors.New("private upstream detail")))
	if err != nil {
		t.Fatal(err)
	}
	var got Error
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !IsInsufficientInstanceCapacity(&got) || !reflect.DeepEqual(&got, want) {
		t.Fatalf("capacity round trip = %+v, want %+v", &got, want)
	}
}
