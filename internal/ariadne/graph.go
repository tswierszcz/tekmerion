package ariadne

import (
	"fmt"
	"reflect"
)

// checkBundleGraph checks all schema-validated records, including ones omitted
// from a query response. A hash-valid bundle can still contain invalid graph
// relationships, so matching hashes alone never authenticates these claims.
func checkBundleGraph(records map[string]map[string]any) error {
	bad := func(r map[string]any, reason string) error {
		key, _ := recordKey(r)
		return fmt.Errorf("bundle graph %s: %s", key, reason)
	}
	lookup := func(kind string, id any) map[string]any {
		value, ok := id.(string)
		if !ok {
			return nil
		}
		return records[kind+":"+value]
	}
	// Index selected ownership once, rather than scanning every class per method.
	type owner struct{ instance, class, hash any }
	selected := map[owner]bool{}
	selectedNames := map[any]any{}
	for _, r := range records {
		if r["record_type"] != "class" {
			continue
		}
		if lookup("component", r["instance_id"]) == nil {
			return bad(r, "unknown class instance")
		}
		chosen := lookup("class", r["selected_class_id"])
		if chosen == nil || chosen["selected"] != true || chosen["class"] != r["class"] {
			return bad(r, "invalid selected class reference")
		}
		if (r["selected"] == true) != (r["class_id"] == r["selected_class_id"]) {
			return bad(r, "selected flag disagrees with selected class identity")
		}
		if r["selected"] == true {
			if previous, exists := selectedNames[r["class"]]; exists && previous != r["class_id"] {
				return bad(r, "multiple selected copies of one class")
			}
			selectedNames[r["class"]] = r["class_id"]
			selected[owner{r["instance_id"], r["class"], r["class_sha256"]}] = true
		}
	}
	methods := map[any]bool{}
	for _, r := range records {
		if r["record_type"] != "node" {
			continue
		}
		canonical := lookup("node", r["canonical_node_id"])
		if canonical == nil {
			return bad(r, "unknown canonical node")
		}
		method, _ := r["method"].(map[string]any)
		switch r["node_kind"] {
		case "synthetic_event":
			if method != nil || r["body"] != "synthetic" {
				return bad(r, "synthetic event carries a method or non-synthetic body")
			}
		case "method", "receiver_specialization":
			if method == nil || r["body"] == "synthetic" {
				return bad(r, "method node requires a method identity and non-synthetic body")
			}
			if method["instance_id"] != nil && lookup("component", method["instance_id"]) == nil {
				return bad(r, "unknown method instance")
			}
			if r["body"] != "external" {
				if !selected[owner{method["instance_id"], method["class"], method["class_sha256"]}] {
					return bad(r, "method has no selected owning class with matching instance and hash")
				}
				if r["access_flags"] == nil {
					return bad(r, "defined method lacks access flags")
				}
			}
			methods[method["method_id"]] = true
		}
		if r["node_kind"] == "receiver_specialization" {
			if r["receiver_type"] == nil || r["canonical_node_id"] == r["node_id"] {
				return bad(r, "specialization needs a receiver and a distinct canonical node")
			}
			if canonical["node_kind"] != "method" || !reflect.DeepEqual(method, canonical["method"]) {
				return bad(r, "specialization differs from its canonical method")
			}
		} else if r["canonical_node_id"] != r["node_id"] || r["receiver_type"] != nil {
			return bad(r, "ordinary node must be canonical and have no receiver")
		}
		source := object(r["source"])
		if source["line_start"] != nil && source["line_end"] != nil && number(source["line_start"]) > number(source["line_end"]) {
			return bad(r, "reversed source range")
		}
	}
	for _, r := range records {
		checkSite := func(v any) error {
			if v != nil && lookup("node", object(v)["caller_node_id"]) == nil {
				return bad(r, "unknown site caller")
			}
			return nil
		}
		switch r["record_type"] {
		case "edge":
			if lookup("node", r["from"]) == nil || lookup("node", r["to"]) == nil {
				return bad(r, "unknown edge endpoint")
			}
			for _, site := range array(r["sites"]) {
				if object(site)["caller_node_id"] != r["from"] {
					return bad(r, "edge site differs from edge caller")
				}
			}
		case "root":
			if lookup("node", r["node_id"]) == nil {
				return bad(r, "unknown root node")
			}
		case "gap":
			if err := checkSite(r["site"]); err != nil {
				return err
			}
			if r["candidate_instance_ids"] != nil {
				for _, id := range array(r["candidate_instance_ids"]) {
					if lookup("component", id) == nil {
						return bad(r, "unknown gap candidate instance")
					}
				}
			}
			if r["candidate_method_ids"] != nil {
				for _, id := range array(r["candidate_method_ids"]) {
					if !methods[id] {
						return bad(r, "unknown gap candidate method")
					}
				}
			}
		case "call":
			if err := checkSite(r["site"]); err != nil {
				return err
			}
			for _, id := range array(r["target_node_ids"]) {
				if lookup("node", id) == nil {
					return bad(r, "unknown call target")
				}
			}
		}
	}
	return nil
}
