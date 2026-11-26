package hunt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
	"github.com/tswierszcz/tekmerion/internal/state"
)

func testContext() Context {
	text := "    Files.write(target, body);"
	citation := recon.Citation{Path: "src/Write.java", SHA: hash([]byte(text)), Start: 20, End: 20}
	method := Method{ID: "write", Method: sourceindex.Method{Class: "fx.Write", Name: "write", Descriptor: "()V", ClassSHA256: hash([]byte("class"))}, InstanceID: "app", Source: citation}
	c := Context{Schema: ContextSchema, Repository: "example", Unit: state.CoverageSeed{ID: hash([]byte("unit"))}, Entry: recon.Entry{ID: "entry", Source: &citation}, PromptSHA: hash([]byte(prompt)), Methods: []Method{method}, Excerpts: []recon.Excerpt{{Citation: citation, Text: text}}, Declarations: []string{"caller may choose a relative name"}, Gaps: []string{"runtime unexamined"}}
	c.Identity = identity(c)
	return c
}
func candidateFor(c Context, m Method, id string) Candidate {
	fact := recon.Fact{Text: "source-derived hypothesis; authority remains unestablished", Origin: "model_inferred", Citations: []recon.Citation{m.Source}}
	// Tests deliberately supply synthetic hypotheses, not vulnerability decisions.
	anchor, _ := citationText(m.Source, c)
	if len(anchor) > 512 {
		anchor = strings.TrimSpace(strings.Split(anchor, "\n")[0])
	}
	return Candidate{LocalID: id, EntryID: c.Entry.ID, TargetID: m.ID, MechanismKey: "missing-containment", RootCause: m.Source, Anchor: anchor, Principal: fact, Resource: fact, ControlledInput: fact, Conditions: []recon.Fact{fact}, Invariant: "A configured directory confines file writes", Mechanism: "Test hypothesis of missing containment at the write", Prediction: "A caller-supplied parent component would create a file outside the configured directory if all prerequisites hold", Experiment: "In a disposable directory invoke the original API once with a normal name and once with ../probe; assert paths and collect resulting files", Controls: "Caller validation and documented powerful API semantics have not been ruled out", Counterarguments: "The caller may already have filesystem authority; this requires independent examination"}
}
func resultFor(c Context) Output {
	return Output{Schema: ResultSchema, InputIdentity: c.Identity, Conclusion: "candidates", Reason: "Source-grounded hypothesis awaiting independent validation", Candidates: []Candidate{candidateFor(c, c.Methods[0], "one")}, Gaps: c.Gaps}
}
func cloneOutput(o Output) Output {
	raw, _ := json.Marshal(o)
	var v Output
	_ = json.Unmarshal(raw, &v)
	return v
}
func TestValidateGroundingAndAuthority(t *testing.T) {
	c := testContext()
	good := resultFor(c)
	if err := good.Validate(c); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Output)
	}{
		{"stale context", func(o *Output) { o.InputIdentity = "wrong" }},
		{"unknown target", func(o *Output) { o.Candidates[0].TargetID = "imaginary" }},
		{"unknown entry", func(o *Output) { o.Candidates[0].EntryID = "imaginary" }},
		{"hallucinated source", func(o *Output) { o.Candidates[0].RootCause.SHA = hash([]byte("wrong")) }},
		{"outside range", func(o *Output) { o.Candidates[0].Principal.Citations[0].End = 999 }},
		{"invented anchor", func(o *Output) { o.Candidates[0].Anchor = "not present" }},
		{"invented authority", func(o *Output) { o.Candidates[0].Principal.Origin = "user_declared" }},
		{"experimental authority", func(o *Output) { o.Candidates[0].Principal.Origin = "experimentally_checked" }},
		{"missing gaps", func(o *Output) { o.Gaps = nil }},
		{"duplicate cause", func(o *Output) { v := o.Candidates[0]; v.LocalID = "two"; o.Candidates = append(o.Candidates, v) }},
		{"confirmation", func(o *Output) { o.Conclusion = "confirmed" }},
		{"no checks", func(o *Output) { o.Conclusion = "no_candidate"; o.Candidates = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := cloneOutput(good)
			tc.change(&o)
			if err := o.Validate(c); err == nil {
				t.Fatal("accepted invalid grounded output")
			}
		})
	}
	raw, _ := json.Marshal(good)
	raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"confirmed":true}`)
	if _, err := ParseOutput(raw, c); err == nil {
		t.Fatal("accepted fabricated decision field")
	}
	c.Entry.ID = "different entry"
	c.Identity = identity(c)
	v := good.Candidates[0]
	v.EntryID = c.Entry.ID
	id, _ := fingerprint(c, v)
	original, _ := fingerprint(testContext(), good.Candidates[0])
	if id != original {
		t.Fatal("entry path changed root cause identity")
	}
	v.MechanismKey = "link-resolution"
	different, _ := fingerprint(c, v)
	if different == id {
		t.Fatal("different mechanisms were collapsed")
	}
}
func TestNoCandidateRequiresEntrySourceReview(t *testing.T) {
	c := testContext()
	o := Output{Schema: ResultSchema, InputIdentity: c.Identity, Conclusion: "no_candidate", Reason: "Only the supplied source was examined", Gaps: c.Gaps, Checks: []Check{{Invariant: "confined writes", Method: "source-review", Observation: "No candidate in this bounded excerpt", Citations: []recon.Citation{c.Methods[0].Source}}}}
	if err := o.Validate(c); err != nil {
		t.Fatal(err)
	}
	o.Checks[0].Method = "graph-found"
	if err := o.Validate(c); err == nil {
		t.Fatal("graph was treated as source review")
	}
}
