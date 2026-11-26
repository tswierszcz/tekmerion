package ariadne

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	contract "github.com/tswierszcz/tekmerion/contracts/ariadne"
)

// This validator deliberately supports only the vocabulary used by the pinned
// response schema. It is not a general JSON Schema implementation. Unknown
// validation keywords fail closed rather than silently weakening acceptance.
func validateResponseSchema(raw []byte) (map[string]any, error) {
	v, err := parseUniqueJSON(raw)
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	if err = json.Unmarshal(contract.Schema, &schema); err != nil {
		return nil, err
	}
	defs := schema["$defs"].(map[string]any)
	// Select the envelope to retain useful field diagnostics.
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("response must be an object")
	}
	name := "DiscoveryResponse"
	if obj["status"] == "error" {
		name = "ErrorResponse"
	} else if obj["operation"] == "reachability" {
		name = "ReachabilityResponse"
	}
	if err := schemaValue(defs[name].(map[string]any), v, defs, "response"); err != nil {
		return nil, err
	}
	return obj, nil
}

// parseUniqueJSON rejects duplicate members and extra documents in both
// response envelopes and individual bundle JSONL records.
func parseUniqueJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := uniqueJSON(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return v, nil
}

func uniqueJSON(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			key := k.(string)
			if _, exists := m[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member %q", key)
			}
			v, err := uniqueJSON(d)
			if err != nil {
				return nil, err
			}
			m[key] = v
		}
		_, err = d.Token()
		return m, err
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, err := uniqueJSON(d)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err = d.Token()
		return a, err
	default:
		return t, nil
	}
}

func schemaValue(s map[string]any, v any, defs map[string]any, path string) error {
	fail := func(reason string) error { return fmt.Errorf("%s: %s", path, reason) }
	for k := range s {
		switch k {
		case "$ref", "type", "const", "enum", "oneOf", "anyOf", "properties", "required", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minLength", "pattern", "minimum", "maximum":
		default:
			return fail("unsupported schema keyword " + k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		target, ok := defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		if !ok || !strings.HasPrefix(ref, "#/$defs/") {
			return fail("unsupported reference")
		}
		return schemaValue(target, v, defs, path)
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if branches, ok := s[key].([]any); ok {
			count := 0
			for _, branch := range branches {
				if schemaValue(branch.(map[string]any), v, defs, path) == nil {
					count++
				}
			}
			if count == 0 || key == "oneOf" && count != 1 {
				return fail("invalid " + key + " value")
			}
		}
	}
	if c, ok := s["const"]; ok && !reflect.DeepEqual(c, v) {
		return fail(fmt.Sprintf("expected %v", c))
	}
	if values, ok := s["enum"].([]any); ok {
		found := false
		for _, c := range values {
			found = found || reflect.DeepEqual(c, v)
		}
		if !found {
			return fail("unsupported value")
		}
	}
	if typ, ok := s["type"].(string); ok {
		valid := false
		switch typ {
		case "object":
			_, valid = v.(map[string]any)
		case "array":
			_, valid = v.([]any)
		case "string":
			_, valid = v.(string)
		case "boolean":
			_, valid = v.(bool)
		case "null":
			valid = v == nil
		case "integer":
			n, ok := v.(json.Number)
			if ok {
				rational, ok := new(big.Rat).SetString(n.String())
				valid = ok && rational.IsInt()
			}
		}
		if !valid {
			return fail("expected " + typ)
		}
	}
	if m, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, k := range required {
			if _, ok := m[k.(string)]; !ok {
				return fail("missing " + k.(string))
			}
		}
		for k, val := range m {
			if sub, ok := props[k].(map[string]any); ok {
				if err := schemaValue(sub, val, defs, path+"."+k); err != nil {
					return err
				}
			} else if s["additionalProperties"] == false {
				return fail("unknown field " + k)
			}
		}
	}
	if a, ok := v.([]any); ok {
		if n, ok := s["minItems"].(float64); ok && len(a) < int(n) {
			return fail("too few items")
		}
		if n, ok := s["maxItems"].(float64); ok && len(a) > int(n) {
			return fail("too many items")
		}
		seen := map[string]bool{}
		for i, val := range a {
			if s["uniqueItems"] == true {
				b, _ := json.Marshal(val)
				if seen[string(b)] {
					return fail("duplicate item")
				}
				seen[string(b)] = true
			}
			if sub, ok := s["items"].(map[string]any); ok {
				if err := schemaValue(sub, val, defs, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	if str, ok := v.(string); ok {
		if n, ok := s["minLength"].(float64); ok && utf8.RuneCountInString(str) < int(n) {
			return fail("string too short")
		}
		if p, ok := s["pattern"].(string); ok {
			r, err := regexp.Compile(p)
			if err != nil || !r.MatchString(str) {
				return fail("invalid string pattern")
			}
		}
	}
	if num, ok := v.(json.Number); ok {
		value, ok := new(big.Rat).SetString(num.String())
		if !ok {
			return fail("invalid number")
		}
		if n, ok := s["minimum"].(float64); ok && value.Cmp(new(big.Rat).SetFloat64(n)) < 0 {
			return fail("below minimum")
		}
		if n, ok := s["maximum"].(float64); ok && value.Cmp(new(big.Rat).SetFloat64(n)) > 0 {
			return fail("above maximum")
		}
	}
	return nil
}
