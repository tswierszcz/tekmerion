package ariadne

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/tswierszcz/tekmerion/contracts/ariadne"
)

func fixtureGraph(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir, "fixtures/bundle/records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]map[string]any{}
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		v, err := parseUniqueJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		r := object(v)
		key, err := recordKey(r)
		if err != nil {
			t.Fatal(err)
		}
		records[key] = r
	}
	return records
}

func addSpecialization(records map[string]map[string]any) {
	base := records["node:n-write"]
	node := map[string]any{}
	for k, v := range base {
		node[k] = v
	}
	node["node_id"] = "n-write-specialized"
	node["node_kind"] = "receiver_specialization"
	node["receiver_type"] = "example.archive.Extractor"
	records["node:n-write-specialized"] = node
}

func TestBundleGraphRelationships(t *testing.T) {
	tests := []struct {
		name, want string
		mutate     func(map[string]map[string]any)
	}{
		{"missing class instance", "unknown class instance", func(r map[string]map[string]any) { r["class:k-extractor"]["instance_id"] = "c-absent" }},
		{"unknown selected class", "invalid selected class", func(r map[string]map[string]any) { r["class:k-extractor"]["selected_class_id"] = "k-absent" }},
		{"selected flag contradiction", "invalid selected class", func(r map[string]map[string]any) { r["class:k-extractor"]["selected"] = false }},
		{"multiple selected copies", "multiple selected copies", func(r map[string]map[string]any) {
			c := map[string]any{}
			for k, v := range r["class:k-extractor"] {
				c[k] = v
			}
			c["class_id"] = "k-duplicate"
			c["selected_class_id"] = "k-duplicate"
			r["class:k-duplicate"] = c
		}},
		{"wrong method hash", "selected owning class", func(r map[string]map[string]any) {
			object(r["node:n-write"]["method"])["class_sha256"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"unknown method instance", "unknown method instance", func(r map[string]map[string]any) { object(r["node:n-write"]["method"])["instance_id"] = "c-missing" }},
		{"missing access flags", "access flags", func(r map[string]map[string]any) { r["node:n-write"]["access_flags"] = nil }},
		{"method without identity", "requires a method", func(r map[string]map[string]any) { r["node:n-write"]["method"] = nil }},
		{"ordinary receiver", "no receiver", func(r map[string]map[string]any) { r["node:n-write"]["receiver_type"] = "example.archive.Extractor" }},
		{"canonical missing", "unknown canonical", func(r map[string]map[string]any) { r["node:n-write"]["canonical_node_id"] = "n-absent" }},
		{"ordinary alias", "must be canonical", func(r map[string]map[string]any) { r["node:n-write"]["canonical_node_id"] = "n-extract" }},
		{"specialization without receiver", "needs a receiver", func(r map[string]map[string]any) {
			addSpecialization(r)
			r["node:n-write-specialized"]["receiver_type"] = nil
		}},
		{"specialization self reference", "distinct canonical", func(r map[string]map[string]any) {
			addSpecialization(r)
			r["node:n-write-specialized"]["canonical_node_id"] = "n-write-specialized"
		}},
		{"specialization method mismatch", "differs from its canonical", func(r map[string]map[string]any) {
			addSpecialization(r)
			r["node:n-write-specialized"]["method"] = r["node:n-extract"]["method"]
		}},
		{"synthetic method", "synthetic event", func(r map[string]map[string]any) {
			r["node:n-unused"]["node_kind"] = "synthetic_event"
			r["node:n-unused"]["body"] = "synthetic"
		}},
		{"synthetic body on method", "non-synthetic body", func(r map[string]map[string]any) { r["node:n-unused"]["body"] = "synthetic" }},
		{"reversed source", "reversed source", func(r map[string]map[string]any) { object(r["node:n-unused"]["source"])["line_end"] = json.Number("1") }},
		{"dangling edge", "unknown edge endpoint", func(r map[string]map[string]any) { r["edge:e-extract-write"]["to"] = "n-absent" }},
		{"wrong edge site", "edge site differs", func(r map[string]map[string]any) {
			object(array(r["edge:e-extract-write"]["sites"])[0])["caller_node_id"] = "n-write"
		}},
		{"dangling root", "unknown root node", func(r map[string]map[string]any) { r["root:r-extract"]["node_id"] = "n-absent" }},
		{"dangling gap site", "unknown site caller", func(r map[string]map[string]any) {
			object(r["gap:g-reflection"]["site"])["caller_node_id"] = "n-absent"
		}},
		{"dangling gap instance", "unknown gap candidate instance", func(r map[string]map[string]any) { r["gap:g-reflection"]["candidate_instance_ids"] = []any{"c-absent"} }},
		{"dangling gap method", "unknown gap candidate method", func(r map[string]map[string]any) { r["gap:g-reflection"]["candidate_method_ids"] = []any{"m-absent"} }},
		{"dangling call target", "unknown call target", func(r map[string]map[string]any) { r["call:s-extract-write"]["target_node_ids"] = []any{"n-absent"} }},
	}
	var schema map[string]any
	if err := json.Unmarshal(contract.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	defs := object(schema["$defs"])
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			records := fixtureGraph(t)
			tc.mutate(records)
			// These cases are schema-valid; graph validation must do the rejecting.
			for key, r := range records {
				if err := schemaValue(object(defs["Record"]), r, defs, key); err != nil {
					t.Fatalf("bad test input: %v", err)
				}
			}
			if err := checkBundleGraph(records); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}

func TestBundleGraphPermittedNodeKinds(t *testing.T) {
	for _, kind := range []string{"method", "receiver_specialization", "external", "synthetic_event", "shadowed_class"} {
		t.Run(kind, func(t *testing.T) {
			records := fixtureGraph(t)
			switch kind {
			case "receiver_specialization":
				addSpecialization(records)
			case "external":
				n := records["node:n-unused"]
				n["body"] = "external"
				n["access_flags"] = nil
				m := object(n["method"])
				m["instance_id"] = nil
				m["class_sha256"] = nil
				m["class"] = "external.Unknown"
			case "synthetic_event":
				n := records["node:n-unused"]
				n["node_kind"] = "synthetic_event"
				n["body"] = "synthetic"
				n["method"] = nil
				n["access_flags"] = nil
			case "shadowed_class":
				c := map[string]any{}
				for k, v := range records["class:k-extractor"] {
					c[k] = v
				}
				c["class_id"] = "k-shadowed"
				c["selected"] = false
				records["class:k-shadowed"] = c
			}
			if err := checkBundleGraph(records); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Publish a self-consistent hash chain so a regression cannot accidentally
// pass merely because hash verification rejects the modified test input.
func publishTestBundle(t *testing.T, data []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(contractDir, "fixtures/bundle")
	identityRaw, err := os.ReadFile(filepath.Join(source, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	identity := decodeDoc(t, identityRaw)
	dataset := object(array(identity["datasets"])[0])
	dataset["sha256"] = sha256Of(data)
	dataset["size_bytes"] = len(data)
	identityRaw, err = json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	analysis := sha256Of(identityRaw)
	manifestRaw, err := os.ReadFile(filepath.Join(source, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := decodeDoc(t, manifestRaw)
	manifest["analysis_id"] = analysis
	manifestRaw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"manifest.json": manifestRaw, "identity.json": identityRaw, "records.jsonl": data} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, analysis
}

func TestHashValidInvalidBundleAttempt(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(contractDir, "fixtures/bundle/records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, want string
		data       []byte
	}{
		{"invalid hidden node", "unknown canonical node", bytes.Replace(data, []byte(`"canonical_node_id":"n-unused"`), []byte(`"canonical_node_id":"n-absent"`), 1)},
		{"invalid record schema", "bundle records.jsonl record", bytes.Replace(data, []byte(`"access_flags":2`), []byte(`"unexpected":true,"access_flags":2`), 1)},
		{"trailing JSON in row", "trailing JSON data", bytes.Replace(data, []byte(`"target_node_ids":["n-write"]}`), []byte(`"target_node_ids":["n-write"]} {}`), 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle, analysis := publishTestBundle(t, tc.data)
			reqRaw := readFixture(t, "path-found-request.json")
			req, _ := ParseRequest(reqRaw)
			original := req.AnalysisID
			req.AnalysisID = analysis
			reqRaw = bytes.ReplaceAll(reqRaw, []byte(original), []byte(analysis))
			raw := bytes.ReplaceAll(readFixture(t, "path-found-response.json"), []byte(original), []byte(analysis))
			if _, err := Check(req, 0, raw); err != nil {
				t.Fatalf("response should be locally valid: %v", err)
			}
			dir := t.TempDir()
			res := &Result{Provenance: ProvenanceFixture, Request: req, RawRequest: reqRaw, RawResponse: raw, Exit: 0, Dir: dir, bundleDir: bundle}
			if err := finish(res, &Attempt{}, time.Now()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if res.Outcome != OutcomeUnusable || res.ValidationScope != "" {
				t.Fatalf("accepted invalid graph: %+v", res)
			}
			attemptRaw, err := os.ReadFile(filepath.Join(dir, "attempt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var attempt Attempt
			if err := json.Unmarshal(attemptRaw, &attempt); err != nil {
				t.Fatal(err)
			}
			if attempt.ResponseHash != sha256Of(raw) || attempt.Diagnostic == "" {
				t.Fatal("invalid attempt lost evidence identity or diagnostic")
			}
		})
	}
}
