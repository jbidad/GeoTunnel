package config

import (
	"bytes"
	"encoding/json"
	"strings"
)

// flexString unmarshals a JSON string or number into a string.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(strings.TrimSpace(s))
		return nil
	}
	*f = flexString(string(b))
	return nil
}

func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(bytes.TrimSpace(b), v)
}

// M is a shorthand for building JSON objects.
type M = map[string]any

// compact drops nil values, empty strings, empty slices/maps and false bools
// from a map (one level), keeping generated configs readable.
func compact(m M) M {
	for k, v := range m {
		switch x := v.(type) {
		case nil:
			delete(m, k)
		case string:
			if x == "" {
				delete(m, k)
			}
		case bool:
			if !x {
				delete(m, k)
			}
		case []string:
			if len(x) == 0 {
				delete(m, k)
			}
		case []any:
			if len(x) == 0 {
				delete(m, k)
			}
		case M:
			if len(x) == 0 {
				delete(m, k)
			}
		case json.RawMessage:
			if len(x) == 0 {
				delete(m, k)
			}
		}
	}
	return m
}
