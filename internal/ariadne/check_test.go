package ariadne

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResponseContractCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contractDir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []struct {
			Path, Definition, Request string
			Schema                    bool `json:"schema_valid"`
			Semantic                  bool `json:"semantic_valid"`
		}
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	for _, c := range suite.Cases {
		if c.Definition != "Response" {
			continue
		}
		t.Run(c.Path, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(contractDir, c.Path))
			if err != nil {
				t.Fatal(err)
			}
			requestPath := c.Request
			if requestPath == "" {
				requestPath = "fixtures/path-found-request.json"
			}
			reqRaw, err := os.ReadFile(filepath.Join(contractDir, requestPath))
			if err != nil {
				t.Fatal(err)
			}
			req, err := ParseRequest(reqRaw)
			if err != nil {
				t.Fatal(err)
			}
			_, schemaErr := validateResponseSchema(body)
			if (schemaErr == nil) != c.Schema {
				t.Fatalf("schema: %v", schemaErr)
			}
			var env Response
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatal(err)
			}
			_, err = Check(req, ExitFor(&env), body)
			if (err == nil) != (c.Schema && c.Semantic) {
				t.Fatalf("unexpected verdict: %v", err)
			}
		})
	}
}

func TestRejectsDamagedEvidence(t *testing.T) {
	req, _ := ParseRequest(readFixture(t, "path-found-request.json"))
	base := readFixture(t, "path-found-response.json")
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown envelope field", func(d map[string]any) { d["extra"] = true }},
		{"missing required field", func(d map[string]any) { delete(d, "warnings") }},
		{"unknown nested field", func(d map[string]any) { object(array(d["results"])[0])["extra"] = true }},
		{"unsupported resolution", func(d map[string]any) { result(d)["resolution"] = "maybe" }},
		{"null count in completed negative", func(d map[string]any) {
			r := result(d)
			r["entries"] = []any{}
			object(r["search"])["state"] = "not_found"
			r["total_entry_count"] = nil
		}},
		{"model contradiction", func(d map[string]any) { object(result(d)["model"])["state"] = "complete_under_declared_model" }},
		{"wrong endpoint", func(d map[string]any) { result(d)["matched_node_ids"] = []any{"n-unused"} }},
		{"missing evidence", func(d map[string]any) { d["evidence"] = []any{} }},
		{"broken edge", func(d map[string]any) {
			for _, v := range array(d["evidence"]) {
				r := object(v)
				if r["record_type"] == "edge" {
					r["to"] = "n-unused"
				}
			}
		}},
		{"duplicate evidence", func(d map[string]any) { a := array(d["evidence"]); d["evidence"] = append(a, a[0]) }},
		{"work limit", func(d map[string]any) { object(d["effective_limits"])["max_work_units"] = 1 }},
		{"path limit", func(d map[string]any) { object(d["effective_limits"])["max_path_nodes"] = 1 }},
		{"count below witnesses", func(d map[string]any) { result(d)["total_entry_count"] = 0 }},
		{"false dispatch", func(d map[string]any) { object(array(result(d)["entries"])[0])["client_dispatch"] = true }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := decodeDoc(t, base)
			tc.mutate(d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(req, 0, raw); err == nil {
				t.Fatal("damaged evidence accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate envelope key", bytes.Replace(base, []byte(`"status": "ok"`), []byte(`"status":"error","status":"ok"`), 1)},
		{"duplicate nested key", bytes.Replace(base, []byte(`"resolution": "matched"`), []byte(`"resolution":"missing","resolution":"matched"`), 1)},
		{"trailing document", append(append([]byte{}, base...), []byte(` {}`)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Check(req, 0, tc.raw); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func decodeDoc(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}
func result(d map[string]any) map[string]any { return object(array(d["results"])[0]) }

func TestUnknownEntryCountAndPartialWitness(t *testing.T) {
	for _, name := range []string{"budget-exhausted", "found-partial-search"} {
		req, _ := ParseRequest(readFixture(t, name+"-request.json"))
		res, err := Check(req, 0, readFixture(t, name+"-response.json"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Results[0].TotalEntryCount != nil {
			t.Fatal("unknown count converted to zero")
		}
		if name == "found-partial-search" && res.Results[0].Search.State != "found" {
			t.Fatal("lost positive witness")
		}
	}
}

func TestBundleBindingAndUnusableAttempt(t *testing.T) {
	reqRaw := readFixture(t, "path-found-request.json")
	req, _ := ParseRequest(reqRaw)
	base := readFixture(t, "path-found-response.json")
	bundle := filepath.Join(contractDir, "fixtures", "bundle")
	if err := checkBundleEvidence(bundle, req, base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong origin", func(d map[string]any) { object(d["provenance"])["producer"] = "someone-else" }},
		{"modified source identity", func(d map[string]any) {
			for _, v := range array(d["evidence"]) {
				r := object(v)
				if r["record_type"] == "node" {
					object(r["source"])["path"] = "other.java"
				}
			}
		}},
		{"modified edge rule", func(d map[string]any) {
			for _, v := range array(d["evidence"]) {
				r := object(v)
				if r["record_type"] == "edge" {
					r["rule"] = "changed"
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decodeDoc(t, base)
			tc.mutate(d)
			raw, _ := json.Marshal(d)
			if _, err := Check(req, 0, raw); err != nil {
				t.Fatalf("test must pass local checks: %v", err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "response.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			res := &Result{Provenance: ProvenanceFixture, Request: req, RawRequest: reqRaw, RawResponse: raw, Exit: 0, Dir: dir, bundleDir: bundle}
			if err := finish(res, &Attempt{}, time.Now()); err == nil {
				t.Fatal("modified bundle evidence accepted")
			}
			if res.Outcome != OutcomeUnusable || res.ValidationScope != "" {
				t.Fatalf("outcome %s scope %s", res.Outcome, res.ValidationScope)
			}
			saved, _ := os.ReadFile(filepath.Join(dir, "response.json"))
			if !bytes.Equal(saved, raw) {
				t.Fatal("raw evidence changed")
			}
			attempt, _ := os.ReadFile(filepath.Join(dir, "attempt.json"))
			if !strings.Contains(string(attempt), `"outcome": "unusable"`) || !strings.Contains(string(attempt), `"diagnostic":`) {
				t.Fatalf("missing rejection diagnostic: %s", attempt)
			}
		})
	}
}

func TestBundleRejectsDifferentRequestedMethod(t *testing.T) {
	req, _ := ParseRequest(readFixture(t, "path-found-request.json"))
	req.Targets[0].MethodID = "m-unused"
	if err := checkBundleEvidence(filepath.Join(contractDir, "fixtures", "bundle"), req, readFixture(t, "path-found-response.json")); err == nil {
		t.Fatal("different target method accepted")
	}
}

func TestRequestedLimitsAndRootSubset(t *testing.T) {
	req, _ := ParseRequest(readFixture(t, "path-found-request.json"))
	body := readFixture(t, "path-found-response.json")
	req.Limits = map[string]int64{"max_path_nodes": 1}
	if _, err := Check(req, 0, body); err == nil {
		t.Fatal("effective limit above requested bound accepted")
	}
	req.Limits = nil
	req.Roots.Selection = "subset"
	req.Roots.NodeIDs = []string{"n-unused"}
	d := decodeDoc(t, body)
	result(d)["root_basis"] = "subset_on_indexed_graph"
	raw, _ := json.Marshal(d)
	if _, err := Check(req, 0, raw); err == nil {
		t.Fatal("witness root outside subset accepted")
	}
}

func TestBundleRejectsCorruptDataset(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(contractDir, "fixtures", "bundle")
	for _, name := range []string{"manifest.json", "identity.json", "records.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "records.jsonl" {
			raw = append(raw, '\n')
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := ParseRequest(readFixture(t, "path-found-request.json"))
	if err := checkBundleEvidence(dir, req, readFixture(t, "path-found-response.json")); err == nil {
		t.Fatal("corrupt dataset accepted")
	}
}

func TestSchemaIntegerPrecision(t *testing.T) {
	base := readFixture(t, "path-found-response.json")
	// Numeric source metadata does not appear in the convenient Response
	// projection; schema validation must reject fractions before evidence use.
	for _, value := range []string{"10.000000000000000001", "9007199254740990.5", "9007199254740991.1", "9007199254740992"} {
		t.Run(value, func(t *testing.T) {
			raw := bytes.Replace(base, []byte(`"line_start": 10`), []byte(`"line_start": `+value), 1)
			if bytes.Equal(raw, base) {
				t.Fatal("source field not replaced")
			}
			if _, err := validateResponseSchema(raw); err == nil {
				t.Fatal("non-integer or out-of-range source line accepted")
			}
		})
	}
	for _, value := range []string{"10.0", "1e1", "9007199254740991"} {
		t.Run("valid_"+value, func(t *testing.T) {
			raw := bytes.Replace(base, []byte(`"line_start": 10`), []byte(`"line_start": `+value), 1)
			if _, err := validateResponseSchema(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEntryCoverageAndGapCounts(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		mutate        func(map[string]any)
	}{
		{"unfinished coverage hidden", "found-partial-search", func(d map[string]any) { result(d)["entries_truncated"] = false }},
		{"omitted entries hidden", "path-found", func(d map[string]any) { result(d)["total_entry_count"] = 2 }},
		{"false entry truncation", "path-found", func(d map[string]any) { result(d)["entries_truncated"] = true }},
		{"relevant gaps exceed total", "path-found", func(d map[string]any) { object(result(d)["model"])["global_gap_count"] = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := ParseRequest(readFixture(t, tc.fixture+"-request.json"))
			d := decodeDoc(t, readFixture(t, tc.fixture+"-response.json"))
			tc.mutate(d)
			raw, _ := json.Marshal(d)
			if _, err := Check(req, 0, raw); err == nil {
				t.Fatal("contradictory coverage accepted")
			}
		})
	}
	req, _ := ParseRequest(readFixture(t, "path-found-request.json"))
	d := decodeDoc(t, readFixture(t, "path-found-response.json"))
	object(result(d)["model"])["global_gap_count"] = 2
	raw, _ := json.Marshal(d)
	if _, err := Check(req, 0, raw); err != nil {
		t.Fatalf("locally consistent count rejected: %v", err)
	}
	if err := checkBundleEvidence(filepath.Join(contractDir, "fixtures/bundle"), req, raw); err == nil {
		t.Fatal("wrong global gap count accepted against bundle")
	}
}
