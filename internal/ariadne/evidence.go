package ariadne

import (
	"encoding/json"
	"fmt"
	"slices"
)

func number(v any) int64           { n, _ := v.(json.Number).Float64(); return int64(n) }
func object(v any) map[string]any  { return v.(map[string]any) }
func array(v any) []any            { return v.([]any) }
func contains(a []any, v any) bool { return slices.Contains(a, v) }

// checkEvidence checks internal consistency only. It cannot authenticate a
// response against the frozen bundle; callers must retain that limitation.
func checkEvidence(req *RequestHead, doc map[string]any) error {
	bad := func(reason string) error { return fmt.Errorf("response evidence: %s", reason) }
	if doc["status"] == "error" {
		return nil
	}
	limits := object(doc["effective_limits"])
	for key, bound := range req.Limits {
		if value, ok := limits[key]; ok && number(value) > bound {
			return bad("effective limit exceeds request")
		}
	}
	if doc["operation"] != "reachability" {
		records, page := array(doc["records"]), object(doc["page"])
		if number(page["returned_count"]) != int64(len(records)) || int64(len(records)) > number(limits["max_records"]) {
			return bad("invalid page count")
		}
		if page["total_count"] != nil && number(page["total_count"]) < int64(len(records)) {
			return bad("total page count below returned count")
		}
		if page["truncated"] == false && page["next_cursor"] != nil {
			return bad("untruncated page carries a cursor")
		}
		kinds := map[any]string{"entries": "root", "methods": "node", "calls": "call", "callers": "edge", "callees": "edge"}
		for _, raw := range records {
			if object(raw)["record_type"] != kinds[doc["operation"]] {
				return bad("record type does not match operation")
			}
		}
		return nil
	}
	index := map[string]map[any]map[string]any{}
	idFields := map[string]string{"node": "node_id", "edge": "edge_id", "root": "root_id", "gap": "gap_id", "class": "class_id", "component": "instance_id", "call": "call_id"}
	for kind := range idFields {
		index[kind] = map[any]map[string]any{}
	}
	for _, raw := range array(doc["evidence"]) {
		r := object(raw)
		kind := r["record_type"].(string)
		id := r[idFields[kind]]
		if index[kind][id] != nil {
			return bad("duplicate evidence identity")
		}
		index[kind][id] = r
	}
	for _, n := range index["node"] {
		src := object(n["source"])
		if src["line_start"] != nil && src["line_end"] != nil && number(src["line_end"]) < number(src["line_start"]) {
			return bad("reversed source range")
		}
	}
	var work int64
	for _, raw := range array(doc["results"]) {
		r := object(raw)
		search, model := object(r["search"]), object(r["model"])
		entries, matched := array(r["entries"]), array(r["matched_node_ids"])
		state, complete := search["state"], search["work_complete"] == true
		work += number(search["work_units"])
		if work > number(limits["max_work_units"]) {
			return bad("work budget exceeded")
		}
		if r["resolution"] != "matched" && (state != "not_evaluated" || len(entries) != 0 || model["state"] != "undetermined") {
			return bad("unresolved target has search evidence")
		}
		if (r["resolution"] == "missing" || r["resolution"] == "shadowed") && len(matched) != 0 {
			return bad("missing/shadowed target has matched nodes")
		}
		if r["resolution"] == "matched" && (len(matched) == 0 || state == "not_evaluated") {
			return bad("matched target was not evaluated")
		}
		if state == "found" {
			if r["resolution"] != "matched" || len(entries) == 0 {
				return bad("found requires a matched target and a witness")
			}
		} else if len(entries) != 0 {
			return bad("non-found search carries witnesses")
		}
		if state == "not_found" && (!complete || r["total_entry_count"] == nil || number(r["total_entry_count"]) != 0) {
			return bad("not_found requires complete search and zero count")
		}
		if state == "incomplete" && (complete || r["total_entry_count"] != nil || search["reason"] == nil) {
			return bad("invalid incomplete search")
		}
		if !complete && (r["total_entry_count"] != nil || search["reason"] == nil) {
			return bad("unfinished search needs unknown count and reason")
		}
		if !complete && r["entries_truncated"] != true {
			return bad("unfinished search hides incomplete entry coverage")
		}
		if total := r["total_entry_count"]; total != nil {
			omitted := number(total) > int64(len(entries))
			if r["entries_truncated"] != omitted {
				return bad("entry truncation disagrees with total count")
			}
		}
		if number(model["global_gap_count"]) < int64(len(array(model["relevant_gap_ids"]))) {
			return bad("relevant gap count exceeds global count")
		}
		if model["state"] == "complete_under_declared_model" && (len(array(model["relevant_gap_ids"])) != 0 || model["scope_uncertain"] != false) {
			return bad("complete model carries uncertainty")
		}
		for _, id := range array(model["relevant_gap_ids"]) {
			if index["gap"][id] == nil {
				return bad("missing gap evidence")
			}
		}
		if int64(len(entries)) > number(limits["max_entries"]) {
			return bad("entry limit exceeded")
		}
		if r["total_entry_count"] != nil && number(r["total_entry_count"]) < int64(len(entries)) {
			return bad("total entry count below witness count")
		}
		basis := "indexed_graph"
		if req.Roots.Selection == "subset" {
			basis = "subset_on_indexed_graph"
		}
		if r["root_basis"] != basis {
			return bad("wrong root basis")
		}
		for _, entry := range entries {
			e := object(entry)
			path := object(e["path"])
			nodes, edges := array(path["node_ids"]), array(path["edge_ids"])
			if req.Roots.Selection == "subset" && !slices.Contains(req.Roots.NodeIDs, e["root_node_id"].(string)) {
				return bad("root outside requested subset")
			}
			if nodes[0] != e["root_node_id"] || len(edges) != len(nodes)-1 {
				return bad("broken path shape")
			}
			if int64(len(nodes)) > number(limits["max_path_nodes"]) {
				return bad("path limit exceeded")
			}
			if path["truncated"] == false {
				if !contains(matched, nodes[len(nodes)-1]) || path["full_node_count"] == nil || number(path["full_node_count"]) != int64(len(nodes)) {
					return bad("invalid path endpoint/count")
				}
			} else if path["full_node_count"] != nil && number(path["full_node_count"]) <= int64(len(nodes)) {
				return bad("truncated path has no omitted nodes")
			}
			for _, id := range nodes {
				if index["node"][id] == nil {
					return bad("missing node evidence")
				}
			}
			chars := map[any]bool{}
			client, supplied := false, false
			for i, id := range edges {
				edge := index["edge"][id]
				if edge == nil || edge["from"] != nodes[i] || edge["to"] != nodes[i+1] {
					return bad("missing or discontinuous edge evidence")
				}
				for _, site := range array(edge["sites"]) {
					if object(site)["caller_node_id"] != edge["from"] {
						return bad("edge site has wrong caller")
					}
				}
				chars[edge["character"]] = true
				client = client || edge["client_dispatch"] == true
				supplied = supplied || edge["supplied_dispatch"] == true
			}

			// Aggregate labels describe the full witness, including an omitted
			// suffix. A prefix can verify only the claims it actually shows.
			if path["truncated"] == false {
				if len(chars) != len(array(e["character"])) || e["client_dispatch"] != client || e["supplied_dispatch"] != supplied {
					return bad("path labels differ from edges")
				}
			} else if client && e["client_dispatch"] != true || supplied && e["supplied_dispatch"] != true {
				return bad("path omits visible dispatch dependence")
			}
			for c := range chars {
				if !contains(array(e["character"]), c) {
					return bad("path omits visible edge character")
				}
			}

		}
	}
	return nil
}
