package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
	"github.com/tswierszcz/tekmerion/internal/state"
)

type Limits struct {
	MaxEntries int `json:"max_entries"`
	MaxPages   int `json:"max_pages_per_operation"`
	MaxBytes   int `json:"max_context_bytes"`
	Lines      int `json:"max_excerpt_lines"`
}

func DefaultLimits() Limits {
	return Limits{MaxEntries: 16, MaxPages: 4, MaxBytes: 64 << 10, Lines: 80}
}
func (l Limits) Validate() error {
	if l.MaxEntries < 1 || l.MaxEntries > 128 || l.MaxPages < 1 || l.MaxPages > 16 || l.MaxBytes < 4096 || l.MaxBytes > 1<<20 || l.Lines < 1 || l.Lines > 200 {
		return fmt.Errorf("invalid bounded Recon context limits")
	}
	return nil
}

type Inventory struct {
	Context Context
	Entries []Entry
}
type node struct {
	ID     string `json:"node_id"`
	Kind   string `json:"node_kind"`
	Method *struct {
		sourceindex.Method
		InstanceID string `json:"instance_id"`
	} `json:"method"`
	Source *sourceindex.AriadneSource `json:"source"`
}

// Build queries frozen graph facts through the strict adapter and saves every
// exchanged document. Only selected, hash-verified excerpts enter model context.
func Build(ctx context.Context, s *state.Store, verified *prepare.Verified, q ariadne.Querier, limits Limits) (*Inventory, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	r := verified.Run
	if r.Analysis == nil || r.Analysis.Roots != "api" {
		return nil, fmt.Errorf("Recon requires a prepared Ariadne bundle with api roots")
	}
	scenario, _ := json.Marshal(verified.Project.Scenario)
	c := Context{Schema: ContextSchema, Repository: r.Source.Repository, Revision: r.Source.Commit, PreparedSHA: hash(verified.RawManifest), SourceSHA: r.Source.TreeSHA256, AppSHA: r.Artifacts.App.SHA256, AnalysisID: r.Analysis.AnalysisID, ScenarioSHA: hash(scenario), CatalogueSHA: hash(catalogue), PromptSHA: hash([]byte(prompt)), Entries: []Entry{}, Excerpts: []Excerpt{}, Calls: []json.RawMessage{}, Declarations: []string{}, Evidence: []QueryEvidence{}, Gaps: []string{}}
	c.Gaps = append(c.Gaps, verified.Gaps...)
	if len(verified.Project.ThreatModel) > 4000 {
		return nil, fmt.Errorf("declared threat model exceeds the Recon fact cap")
	}
	if len(verified.Project.ThreatModel) > 0 && string(verified.Project.ThreatModel) != "null" {
		c.Declarations = append(c.Declarations, declarations(verified.Project.ThreatModel)...)
	} else {
		c.Gaps = append(c.Gaps, "user threat model is unspecified; no attacker authority is established")
	}
	records := map[string][]json.RawMessage{}
	for _, op := range []string{"entries", "methods", "calls"} {
		var cursor *string
		cursors := map[string]bool{}
		for page := 0; page < limits.MaxPages; page++ {
			body := map[string]any{"schema_version": ariadne.QuerySchema, "analysis_id": c.AnalysisID, "request_id": fmt.Sprintf("recon-%s-%d", op, page), "operation": op, "limits": map[string]int{"max_records": 128}, "cursor": cursor}
			if op == "methods" {
				rootIDs := []string{}
				for _, raw := range records["entries"] {
					var root struct {
						NodeID string `json:"node_id"`
					}
					if err := jsonx.Decode(raw, &root, true); err != nil {
						return nil, err
					}
					rootIDs = append(rootIDs, root.NodeID)
				}
				if len(rootIDs) == 0 {
					break
				}
				body["filters"] = map[string]any{"node_ids": rootIDs}
			}
			request, _ := json.Marshal(body)
			a, err := s.Put(ctx, request, "application/json")
			if err != nil {
				return nil, err
			}
			result, queryErr := q.Query(ctx, request)
			evidence := QueryEvidence{Operation: op, RequestSHA: a.SHA}
			if result != nil {
				evidence.Outcome, evidence.Provenance, evidence.ValidationScope = result.Outcome, result.Provenance, result.ValidationScope
				if result.RawResponse != nil {
					a, err := s.Put(ctx, result.RawResponse, "application/json")
					if err != nil {
						return nil, err
					}
					evidence.ResponseSHA = a.SHA
				}
				if result.Dir != "" {
					raw, err := prepare.ReadFile(result.Dir, "attempt.json", 1<<20)
					if err != nil {
						return nil, err
					}
					a, err := s.Put(ctx, raw, "application/json")
					if err != nil {
						return nil, err
					}
					evidence.InvocationSHA = a.SHA
				}
				if len(result.Stderr) > 0 {
					if _, err := s.Put(ctx, result.Stderr, "text/plain"); err != nil {
						return nil, err
					}
				}
			}
			if queryErr != nil {
				evidence.Diagnostic = queryErr.Error()
				c.Evidence = append(c.Evidence, evidence)
				return nil, fmt.Errorf("unusable Ariadne %s evidence: %w", op, queryErr)
			}
			c.Evidence = append(c.Evidence, evidence)
			if result == nil || result.Outcome != ariadne.OutcomeResult || result.ValidationScope != "bundle" {
				return nil, fmt.Errorf("Recon needs bundle-validated %s evidence", op)
			}
			var response struct {
				Records []json.RawMessage `json:"records"`
				Page    struct {
					Next      *string `json:"next_cursor"`
					Truncated bool    `json:"truncated"`
					Complete  bool    `json:"work_complete"`
				} `json:"page"`
			}
			if err := jsonx.Decode(result.RawResponse, &response, true); err != nil {
				return nil, err
			}
			records[op] = append(records[op], response.Records...)
			if !response.Page.Complete {
				c.Gaps = append(c.Gaps, op+" discovery stopped before work completed")
			}
			if response.Page.Next == nil {
				if response.Page.Truncated {
					c.Gaps = append(c.Gaps, op+" discovery truncated without a continuation")
				}
				break
			}
			if cursors[*response.Page.Next] {
				return nil, fmt.Errorf("Ariadne pagination repeated a cursor")
			}
			cursors[*response.Page.Next] = true
			cursor = response.Page.Next
			if page+1 == limits.MaxPages {
				c.Gaps = append(c.Gaps, op+" discovery deferred after page limit")
			}
		}
	}
	nodes := map[string]node{}
	for _, raw := range records["methods"] {
		var n node
		if err := jsonx.Decode(raw, &n, true); err != nil {
			return nil, err
		}
		if _, exists := nodes[n.ID]; exists {
			return nil, fmt.Errorf("duplicate method node across discovery pages")
		}
		nodes[n.ID] = n
	}
	appArtifacts := map[string]string{}
	for _, f := range append([]manifest.File{r.Artifacts.App}, r.Artifacts.Deps...) {
		appArtifacts[f.Path] = f.SHA256
	}
	inventory := map[string]*Entry{}
	for _, raw := range records["entries"] {
		var root struct {
			NodeID string `json:"node_id"`
		}
		if err := jsonx.Decode(raw, &root, true); err != nil {
			return nil, err
		}
		n, ok := nodes[root.NodeID]
		if !ok || n.Method == nil {
			c.Gaps = append(c.Gaps, "API root lacks a method in bounded discovery: "+root.NodeID)
			continue
		}
		m := n.Method.Method
		id := stable(c.Repository, methodKey(m))
		if existing := inventory[id]; existing != nil {
			if existing.Method != m || existing.InstanceID != n.Method.InstanceID {
				return nil, fmt.Errorf("canonical API identity collision")
			}
			existing.RootNodes = append(existing.RootNodes, root.NodeID)
			continue
		}
		entry := &Entry{ID: id, Method: m, InstanceID: n.Method.InstanceID, RootNodes: []string{root.NodeID}, Subsystem: m.Class}
		if split := strings.LastIndexByte(m.Class, '.'); split >= 0 {
			entry.Subsystem = m.Class[:split]
		}
		location := verified.Index.Resolve(m, n.Source)
		if m.ClassSHA256 != "" && appArtifacts[location.Artifact] != "" && location.Binding == sourceindex.BindingBuildVerified && location.Path != nil && location.SourceSHA256 != nil && location.LineStart != nil && location.LineEnd != nil && len(location.Conflicts) == 0 {
			entry.Source = &Citation{Path: *location.Path, SHA: *location.SourceSHA256, Start: *location.LineStart, End: *location.LineEnd}
			entry.ArtifactSHA = appArtifacts[location.Artifact]
		} else {
			entry.SelectionReason = "exact source binding unavailable or conflicting"
		}
		inventory[id] = entry
	}
	entries := []Entry{}
	for _, entry := range inventory {
		sort.Strings(entry.RootNodes)
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for i := range entries {
		entry := entries[i]
		if len(c.Entries) >= limits.MaxEntries {
			entries[i].SelectionReason = "entry context limit"
			c.DeferredCount++
			continue
		}
		var excerpt *Excerpt
		var sourceBytes []byte
		if entry.Source != nil {
			raw, err := prepare.ReadFile(verified.Work+"/src", entry.Source.Path, 2<<20)
			if err != nil {
				return nil, err
			}
			if hash(raw) != entry.Source.SHA || !utf8.Valid(raw) {
				return nil, fmt.Errorf("source excerpt changed or is not UTF-8")
			}
			sourceBytes = raw
			lines := strings.Split(string(raw), "\n")
			start, end := max(1, entry.Source.Start-min(8, limits.Lines/4)), entry.Source.End
			if start < 1 || end < start || end > len(lines) {
				return nil, fmt.Errorf("indexed source range is outside its file")
			}
			end = min(end, start+limits.Lines-1)
			excerpt = &Excerpt{Kind: "method", Citation: Citation{Path: entry.Source.Path, SHA: entry.Source.SHA, Start: start, End: end}, Text: strings.Join(lines[start-1:end], "\n")}
		}
		beforeEntries, beforeExcerpts := len(c.Entries), len(c.Excerpts)
		c.Entries = append(c.Entries, entry)
		if excerpt != nil {
			c.Excerpts = append(c.Excerpts, *excerpt)
		}
		raw, _ := json.Marshal(c)
		if len(raw) > limits.MaxBytes-2048 {
			c.Entries = c.Entries[:beforeEntries]
			c.Excerpts = c.Excerpts[:beforeExcerpts]
			entries[i].SelectionReason = "context byte limit"
			c.DeferredCount++
			continue
		}
		if sourceBytes != nil {
			if _, err := s.Put(ctx, sourceBytes, "text/x-java"); err != nil {
				return nil, err
			}
		}
	}
	// Retain relevant bounded calls as graph facts, without implying a complete
	// source-to-sink trace or claiming a security effect.
	classes := map[string]bool{}
	for _, entry := range c.Entries {
		classes[entry.Method.Class] = true
	}
	for _, raw := range records["calls"] {
		var call struct {
			DeclaredClass string `json:"declared_class"`
		}
		if err := jsonx.Decode(raw, &call, true); err != nil {
			return nil, err
		}
		if !classes[call.DeclaredClass] && call.DeclaredClass != "java.nio.file.Files" && call.DeclaredClass != "java.nio.file.Path" && call.DeclaredClass != "java.io.File" {
			continue
		}
		c.Calls = append(c.Calls, raw)
		data, _ := json.Marshal(c)
		if len(data) > limits.MaxBytes-1024 {
			c.Calls = c.Calls[:len(c.Calls)-1]
			c.Gaps = append(c.Gaps, "call context deferred after byte limit")
			break
		}
	}
	if err := addDocuments(ctx, s, verified, &c, limits); err != nil {
		return nil, err
	}
	// Retain frozen bundle metadata; full graph datasets/binaries remain in
	// the prepared directory under their recorded hashes.
	if raw, err := prepare.ReadFile(verified.Work, "bundle/identity.json", 16<<20); err != nil {
		return nil, err
	} else {
		if _, err := s.Put(ctx, raw, "application/json"); err != nil {
			return nil, err
		}
		var identity struct {
			Coverage struct {
				Limits []string `json:"limits"`
			} `json:"coverage"`
			FixedPoint struct {
				State   string   `json:"state"`
				Reasons []string `json:"reasons"`
			} `json:"fixed_point"`
		}
		if err := jsonx.Decode(raw, &identity, true); err != nil {
			return nil, err
		}
		for _, limit := range identity.Coverage.Limits {
			c.Gaps = append(c.Gaps, "Ariadne coverage: "+limit)
		}
		if identity.FixedPoint.State != "" && identity.FixedPoint.State != "converged" {
			c.Gaps = append(c.Gaps, "Ariadne fixed point is not converged")
		}
	}
	c.Gaps = append(c.Gaps, "full bytecode/bundle datasets remain in the prepared work directory; only selected source/query evidence is copied", "static API discovery does not establish runtime behavior or deployment authority")
	checked, err := prepare.Verify(verified.Work)
	if err != nil {
		return nil, err
	}
	if hash(checked.RawManifest) != c.PreparedSHA {
		return nil, fmt.Errorf("preparation changed during Recon context collection")
	}
	if c.DeferredCount > 0 {
		c.Gaps = append(c.Gaps, "known API entries deferred by context limits")
	}
	if len(entries) == 0 {
		c.Gaps = append(c.Gaps, "no concrete API methods were resolved; absence is not a safety conclusion")
	}
	c.Identity = contextIdentity(c)
	raw, _ := json.Marshal(c)
	if len(raw) > limits.MaxBytes {
		return nil, fmt.Errorf("Recon metadata exceeds context cap")
	}
	// Save the verified preparation and index as immutable evidence as well.
	bundleManifest, err := prepare.ReadFile(verified.Work, "bundle/manifest.json", 2<<20)
	if err != nil {
		return nil, err
	}
	if _, err := s.Put(ctx, bundleManifest, "application/json"); err != nil {
		return nil, err
	}
	for _, raw := range [][]byte{verified.RawManifest, verified.RawIndex, catalogue, []byte(prompt)} {
		if _, err := s.Put(ctx, raw, "application/json"); err != nil {
			return nil, err
		}
	}
	return &Inventory{Context: c, Entries: entries}, nil
}

// declarations splits a declared threat model into individually quotable
// statements, because Hunt accepts a user_declared fact only when its text
// equals one declaration exactly. A JSON string is one statement; an array of
// strings or an object whose values are all strings yields one statement per
// value, in document order (object keys only label the values). Any other
// shape, or an empty value, is kept verbatim as a single declaration.
func declarations(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil && len(list) > 0 && !slices.Contains(list, "") {
		return list
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err == nil && t == json.Delim('{') {
		values := []string{}
		for d.More() {
			if _, err := d.Token(); err != nil {
				return []string{string(raw)}
			}
			t, err := d.Token()
			v, ok := t.(string)
			if err != nil || !ok || v == "" {
				return []string{string(raw)}
			}
			values = append(values, v)
		}
		if len(values) > 0 {
			return values
		}
	}
	return []string{string(raw)}
}
