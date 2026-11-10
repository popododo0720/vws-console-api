// Package console is the JSON API the Next.js console calls.
//
// decode refuses a JSON body whose object repeats a key, or whose key
// matches a known field only by case, before the body ever reaches
// encoding/json's own field matching. Both read as the last value winning
// or a field being set that the caller meant to clear (#599).
package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return resource.TooLarge("body exceeds the limit")
		}
		return resource.Invalid("body", "malformed json")
	}
	if err := checkAmbiguousKeys(body, reflect.TypeOf(dst)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return resource.Invalid("body", "malformed json")
	}
	return nil
}

// checkAmbiguousKeys walks raw alongside t's fields and refuses a key that
// repeats another key of the same object, or that matches a field's json
// name only case-insensitively. A malformed body is left to the real
// decoder, which reports it.
func checkAmbiguousKeys(raw []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return walkValue(dec, t)
}

func walkValue(dec *json.Decoder, t reflect.Type) error {
	for t != nil && (t.Kind() == reflect.Pointer || t.Kind() == reflect.Interface) {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return nil //nolint:nilerr // a malformed body is left to the real decoder, which reports it
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return walkObject(dec, t)
	case '[':
		return walkArray(dec, t)
	}
	return nil
}

func walkObject(dec *json.Decoder, t reflect.Type) error {
	fields, isMap := objectFields(t)
	seen := make(map[string]string)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil //nolint:nilerr // a malformed body is left to the real decoder, which reports it
		}
		key, ok := tok.(string)
		if !ok {
			return nil
		}
		lower := strings.ToLower(key)
		if prev, dup := seen[lower]; dup {
			return resource.Invalid(key, "repeats the key \""+prev+"\" in the same object")
		}
		seen[lower] = key
		var child reflect.Type
		switch {
		case isMap:
			child = t.Elem()
		case fields != nil:
			if f, ok := fields[lower]; ok {
				if f.name != key {
					return resource.Invalid(key, "matches the field \""+f.name+"\" only by case")
				}
				child = f.typ
			}
		}
		if err := walkValue(dec, child); err != nil {
			return err
		}
	}
	dec.Token() //nolint:errcheck // the closing delimiter carries no information we need
	return nil
}

func walkArray(dec *json.Decoder, t reflect.Type) error {
	var elem reflect.Type
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		elem = t.Elem()
	}
	for dec.More() {
		if err := walkValue(dec, elem); err != nil {
			return err
		}
	}
	dec.Token() //nolint:errcheck // the closing delimiter carries no information we need
	return nil
}

type fieldInfo struct {
	name string
	typ  reflect.Type
}

// objectFields returns t's JSON fields by lowercased name, or reports t is a
// map, whose keys are data rather than field names and so are checked only
// for an exact repeat.
func objectFields(t reflect.Type) (map[string]fieldInfo, bool) {
	if t == nil {
		return nil, false
	}
	if t.Kind() == reflect.Map {
		return nil, true
	}
	if t.Kind() != reflect.Struct {
		return nil, false
	}
	out := make(map[string]fieldInfo, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[strings.ToLower(name)] = fieldInfo{name: name, typ: f.Type}
	}
	return out, false
}
