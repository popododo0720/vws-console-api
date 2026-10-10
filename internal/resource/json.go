package resource

import "encoding/json"

func marshalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, Internal(err)
	}
	return b, nil
}

func unmarshalJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return Invalid("body", "malformed json")
	}
	return nil
}
