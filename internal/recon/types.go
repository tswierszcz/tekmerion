// Package recon builds bounded source/API context and validates architecture
// observations before seeding persistent, still-unchecked research coverage.
package recon

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

const ContextSchema = "tekmerion-recon-context-1"
const ResultSchema = "tekmerion-recon-result-1"
const RunSchema = "tekmerion-recon-run-1"
const PromptRevision = "recon-1"

//go:embed catalogue.json
var catalogue []byte

//go:embed prompt.txt
var prompt string

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func stable(values ...string) string        { raw, _ := json.Marshal(values); return hash(raw) }
func methodKey(m sourceindex.Method) string { return m.Class + "#" + m.Name + m.Descriptor }

type Citation struct {
	Path  string `json:"path"`
	SHA   string `json:"sha256"`
	Start int    `json:"line_start"`
	End   int    `json:"line_end"`
}
type Excerpt struct {
	Kind string `json:"kind"`
	Citation
	Text string `json:"text"`
}
type Entry struct {
	ID              string             `json:"entry_id"`
	Method          sourceindex.Method `json:"method"`
	InstanceID      string             `json:"instance_id"`
	ArtifactSHA     string             `json:"artifact_sha256"`
	Subsystem       string             `json:"subsystem"`
	RootNodes       []string           `json:"root_node_ids"`
	Source          *Citation          `json:"source"`
	SelectionReason string             `json:"selection_reason,omitempty"`
}
type QueryEvidence struct {
	InvocationSHA   string `json:"invocation_sha256,omitempty"`
	Operation       string `json:"operation"`
	RequestSHA      string `json:"request_sha256"`
	ResponseSHA     string `json:"response_sha256,omitempty"`
	Outcome         string `json:"outcome"`
	Provenance      string `json:"provenance"`
	ValidationScope string `json:"validation_scope"`
	Diagnostic      string `json:"diagnostic,omitempty"`
}
type Context struct {
	Identity      string            `json:"input_identity"`
	Schema        string            `json:"schema_version"`
	Repository    string            `json:"repository"`
	Revision      string            `json:"revision"`
	PreparedSHA   string            `json:"prepared_manifest_sha256"`
	SourceSHA     string            `json:"source_tree_sha256"`
	AppSHA        string            `json:"app_sha256"`
	AnalysisID    string            `json:"analysis_id"`
	ScenarioSHA   string            `json:"scenario_sha256"`
	CatalogueSHA  string            `json:"catalogue_sha256"`
	PromptSHA     string            `json:"prompt_sha256"`
	Entries       []Entry           `json:"entries"`
	Excerpts      []Excerpt         `json:"excerpts"`
	Calls         []json.RawMessage `json:"calls"`
	Declarations  []string          `json:"user_declarations"`
	Evidence      []QueryEvidence   `json:"ariadne_evidence"`
	DeferredCount int               `json:"deferred_entries"`
	Gaps          []string          `json:"gaps"`
}
type Fact struct {
	Text      string     `json:"text"`
	Origin    string     `json:"origin"`
	Citations []Citation `json:"citations"`
}
type Proposal struct {
	EntryID    string     `json:"entry_id"`
	PropertyID string     `json:"property_id"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason"`
	Citations  []Citation `json:"citations"`
}
type Output struct {
	InputIdentity   string     `json:"input_identity"`
	Schema          string     `json:"schema_version"`
	Summary         string     `json:"summary"`
	Principals      []Fact     `json:"principals"`
	Resources       []Fact     `json:"resources"`
	Inputs          []Fact     `json:"inputs"`
	Transformations []Fact     `json:"transformations"`
	Controls        []Fact     `json:"controls"`
	Assumptions     []Fact     `json:"assumptions"`
	Coverage        []Proposal `json:"coverage"`
	Gaps            []string   `json:"gaps"`
}

func checkCitation(c Citation, context Context) error {
	if c.Start < 1 || c.End < c.Start {
		return fmt.Errorf("invalid citation range")
	}
	for _, e := range context.Excerpts {
		if c.Path == e.Path && c.SHA == e.SHA && c.Start >= e.Start && c.End <= e.End {
			return nil
		}
	}
	return fmt.Errorf("citation is outside saved source excerpts: %s", c.Path)
}
func (o Output) Validate(context Context) error {
	if o.InputIdentity != context.Identity || context.Identity != contextIdentity(context) {
		return fmt.Errorf("Recon output belongs to a different source/API context")
	}
	if o.Schema != ResultSchema || strings.TrimSpace(o.Summary) == "" || len(o.Summary) > 12000 || len(strings.Fields(o.Summary)) > 1000 {
		return fmt.Errorf("Recon output needs its version and a summary of at most 1000 words")
	}
	entries := map[string]Entry{}
	for _, entry := range context.Entries {
		entries[entry.ID] = entry
	}
	for _, group := range [][]Fact{o.Principals, o.Resources, o.Inputs, o.Transformations, o.Controls, o.Assumptions} {
		for _, fact := range group {
			if strings.TrimSpace(fact.Text) == "" || len(fact.Text) > 4000 {
				return fmt.Errorf("empty or oversized Recon fact")
			}
			if fact.Origin == "user_declared" {
				found := false
				for _, d := range context.Declarations {
					found = found || d == fact.Text
				}
				if !found {
					return fmt.Errorf("model broadened or invented a declared assumption")
				}
			} else if fact.Origin != "model_inferred" {
				return fmt.Errorf("unsupported fact origin in Recon")
			}
			if fact.Origin == "model_inferred" && len(fact.Citations) == 0 {
				return fmt.Errorf("model fact lacks source citations")
			}
			for _, c := range fact.Citations {
				if err := checkCitation(c, context); err != nil {
					return err
				}
			}
		}
	}
	for _, declaration := range context.Declarations {
		retained := false
		for _, a := range o.Assumptions {
			retained = retained || a.Origin == "user_declared" && a.Text == declaration
		}
		if !retained {
			return fmt.Errorf("Recon omitted a user-declared assumption")
		}
	}
	for _, gap := range context.Gaps {
		retained := false
		for _, known := range o.Gaps {
			retained = retained || gap == known
		}
		if !retained {
			return fmt.Errorf("Recon omitted a known input/analysis gap")
		}
	}
	seen := map[string]bool{}
	for _, p := range o.Coverage {
		entry, ok := entries[p.EntryID]
		if !ok || p.PropertyID != "file-confinement" || seen[p.EntryID] {
			return fmt.Errorf("unknown or duplicate coverage selector/property")
		}
		seen[p.EntryID] = true
		if p.Status != "planned" && p.Status != "blocked" && p.Status != "deferred" && p.Status != "out_of_scope" {
			return fmt.Errorf("Recon cannot mark work checked or accept a finding")
		}
		if p.Status != "planned" && strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("non-planned coverage needs a reason")
		}
		if entry.Source == nil {
			if p.Status != "blocked" {
				return fmt.Errorf("entry without source must remain blocked")
			}
		} else {
			cited := false
			for _, c := range p.Citations {
				if err := checkCitation(c, context); err != nil {
					return err
				}
				cited = cited || c.Path == entry.Source.Path && c.SHA == entry.Source.SHA && c.End >= entry.Source.Start && c.Start <= entry.Source.End
			}
			if !cited {
				return fmt.Errorf("coverage omits its entry source")
			}
		}
	}
	if len(seen) != len(entries) {
		return fmt.Errorf("Recon omitted supplied API surfaces")
	}
	for _, gap := range o.Gaps {
		if strings.TrimSpace(gap) == "" {
			return fmt.Errorf("empty Recon gap")
		}
	}
	return nil
}

// Context identity excludes invocation timing/paths and the preparation's
// presentation bytes, but includes all source/API content admitted to prompts.
func contextIdentity(c Context) string {
	semantic := struct {
		Repository, Revision, Source, App, Analysis, Scenario, Catalogue, Prompt string
		Entries                                                                  []Entry
		Excerpts                                                                 []Excerpt
		Calls                                                                    []json.RawMessage
		Declarations, Gaps                                                       []string
		Deferred                                                                 int
	}{c.Repository, c.Revision, c.SourceSHA, c.AppSHA, c.AnalysisID, c.ScenarioSHA, c.CatalogueSHA, c.PromptSHA, c.Entries, c.Excerpts, c.Calls, c.Declarations, c.Gaps, c.DeferredCount}
	raw, _ := json.Marshal(semantic)
	return hash(raw)
}
