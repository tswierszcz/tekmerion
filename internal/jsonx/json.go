// Package jsonx provides strict single-document JSON decoding for controller inputs.
package jsonx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

func Decode(raw []byte, dst any, unknown bool) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("invalid UTF-8 JSON")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if err := walk(check); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !unknown {
		d.DisallowUnknownFields()
	}
	return d.Decode(dst)
}
func walk(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			k := key.(string)
			if seen[k] {
				return fmt.Errorf("duplicate JSON member %q", k)
			}
			seen[k] = true
			if err := walk(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case json.Delim('['):
		for d.More() {
			if err := walk(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	return nil
}
