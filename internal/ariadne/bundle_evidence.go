package ariadne

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	contract "github.com/tswierszcz/tekmerion/contracts/ariadne"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// checkBundleEvidence binds copied records and roots to hash-verified datasets.
// Error envelopes do not claim graph facts and need no readable bundle.
func checkBundleEvidence(dir string, req *RequestHead, raw []byte) error {
	doc, err := validateResponseSchema(raw)
	if err != nil {
		return err
	}
	if doc["status"] == "error" {
		return nil
	}
	b, err := LoadBundle(dir)
	if err != nil {
		return err
	}
	if b.AnalysisID != req.AnalysisID || sha256Of(b.RawIdentity) != b.AnalysisID {
		return fmt.Errorf("bundle identity hash/analysis mismatch")
	}
	var identity struct {
		Provenance map[string]any `json:"provenance"`
		Datasets   []struct {
			Path  string `json:"path"`
			SHA   string `json:"sha256"`
			Size  int64  `json:"size_bytes"`
			Count int    `json:"record_count"`
		} `json:"datasets"`
	}
	if err := json.Unmarshal(b.RawIdentity, &identity); err != nil {
		return err
	}
	if !reflect.DeepEqual(doc["provenance"], identity.Provenance) {
		return fmt.Errorf("response provenance differs from bundle")
	}
	var schema map[string]any
	if err := json.Unmarshal(contract.Schema, &schema); err != nil {
		return err
	}
	defs := schema["$defs"].(map[string]any)
	records := map[string]map[string]any{}
	roots := map[any]bool{}
	paths := map[string]bool{}
	var gapCount int64
	for _, dataset := range identity.Datasets {
		if paths[dataset.Path] {
			return fmt.Errorf("duplicate bundle dataset")
		}
		paths[dataset.Path] = true
		data, err := readBundleMember(dir, dataset.Path)
		if err != nil {
			return err
		}
		if int64(len(data)) != dataset.Size || sha256Of(data) != dataset.SHA {
			return fmt.Errorf("bundle dataset %s hash/size mismatch", dataset.Path)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			return fmt.Errorf("bundle dataset must end in LF")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), 64*1024*1024)
		count := 0
		for scanner.Scan() {
			v, err := parseUniqueJSON(scanner.Bytes())
			if err != nil {
				return err
			}
			r, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("bundle record must be object")
			}
			if err := schemaValue(defs["Record"].(map[string]any), r, defs, fmt.Sprintf("bundle %s record %d", dataset.Path, count+1)); err != nil {
				return err
			}
			key, err := recordKey(r)
			if err != nil {
				return err
			}
			if records[key] != nil {
				return fmt.Errorf("duplicate bundle record %s", key)
			}
			records[key] = r
			if r["record_type"] == "gap" {
				gapCount++
			}
			if r["record_type"] == "root" {
				roots[r["node_id"]] = true
			}
			count++
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if count != dataset.Count {
			return fmt.Errorf("bundle dataset record count mismatch")
		}
	}
	if err := checkBundleGraph(records); err != nil {
		return err
	}
	field := "evidence"
	if doc["operation"] != "reachability" {
		field = "records"
	}
	for _, v := range array(doc[field]) {
		r := object(v)
		key, err := recordKey(r)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(r, records[key]) {
			return fmt.Errorf("response record %s differs from frozen bundle", key)
		}
	}
	if doc["operation"] == "reachability" {
		if req.Roots.Selection == "subset" {
			for _, id := range req.Roots.NodeIDs {
				if !roots[id] {
					return fmt.Errorf("requested root is outside bundle")
				}
			}
		}
		for i, v := range array(doc["results"]) {
			r := object(v)
			if number(object(r["model"])["global_gap_count"]) != gapCount {
				return fmt.Errorf("global gap count differs from bundle")
			}
			for _, id := range array(r["matched_node_ids"]) {
				node := records["node:"+id.(string)]
				if node == nil {
					return fmt.Errorf("matched node is outside bundle")
				}
				method, ok := node["method"].(map[string]any)
				if !ok {
					return fmt.Errorf("matched node has no method identity")
				}
				target := req.Targets[i]
				if target.MethodID != "" && method["method_id"] != target.MethodID {
					return fmt.Errorf("matched method differs from requested identity")
				}
				for field, value := range target.Selector {
					if method[field] != value {
						return fmt.Errorf("matched method differs from requested selector %s", field)
					}
				}
			}
			for _, e := range array(r["entries"]) {
				if !roots[object(e)["root_node_id"]] {
					return fmt.Errorf("witness root is outside bundle")
				}
			}
		}
	}
	return nil
}

func recordKey(r map[string]any) (string, error) {
	fields := map[string]string{"node": "node_id", "edge": "edge_id", "root": "root_id", "gap": "gap_id", "class": "class_id", "component": "instance_id", "call": "call_id"}
	kind, ok := r["record_type"].(string)
	if !ok || fields[kind] == "" {
		return "", fmt.Errorf("unknown bundle record type")
	}
	id, ok := r[fields[kind]].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("missing bundle record identity")
	}
	return kind + ":" + id, nil
}

func readBundleMember(dir, rel string) ([]byte, error) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("unsafe bundle member %q", rel)
	}
	current := dir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink bundle member %q", rel)
		}
	}
	info, err := os.Stat(current)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("bundle member is not a regular file")
	}
	return os.ReadFile(current)
}
