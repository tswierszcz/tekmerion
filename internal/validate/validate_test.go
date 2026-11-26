package validate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/recon"
)

func testContext() Context {
	q := recon.Citation{Path: "fx/A.java", SHA: hash([]byte("a")), Start: 10, End: 20}
	c := Context{Schema: ContextSchema, PromptSHA: hash([]byte(prompt)), CandidateID: "sha256:c", Canonical: "cause", RootCause: q, Anchor: "write",
		Claims:     []Claim{{ID: "o1.principal", Text: "caller"}, {ID: "o1.effect", Text: "file outside"}},
		Static:     []Static{},
		Experiment: ExperimentEvidence{Reproduction: "reproduced", Cases: []CaseEvidence{{ID: "traversal"}}},
		Excerpts:   []recon.Excerpt{{Kind: "method", Citation: recon.Citation{Path: q.Path, SHA: q.SHA, Start: 5, End: 25}, Text: "..."}},
		Gaps:       []string{"bounded"}, Declarations: []string{}}
	c.Identity = identity(c)
	return c
}

func supportedOutput(c Context) Output {
	o := Output{Schema: ResultSchema, InputIdentity: c.Identity, Decision: "supported", Reason: "test", Controls: []Control{{Text: "no containment", Citations: []recon.Citation{c.RootCause}}}, Unresolved: []string{}, Gaps: c.Gaps}
	for _, cl := range c.Claims {
		o.Claims = append(o.Claims, Assessment{Claim: cl.ID, Status: "supported", Observation: "seen", Citations: []recon.Citation{c.RootCause}, Evidence: []string{"traversal"}})
	}
	return o
}

func clone(o Output) Output {
	raw, _ := json.Marshal(o)
	var v Output
	_ = json.Unmarshal(raw, &v)
	return v
}

func TestOutputValidation(t *testing.T) {
	c := testContext()
	good := supportedOutput(c)
	if err := good.Validate(c); err != nil {
		t.Fatal(err)
	}
	if err := Offline(c).Validate(c); err != nil {
		t.Fatal("offline output invalid: ", err)
	}
	for name, change := range map[string]func(*Output){
		"stale context":      func(o *Output) { o.InputIdentity = "x" },
		"missing claim":      func(o *Output) { o.Claims = o.Claims[:1] },
		"unknown claim":      func(o *Output) { o.Claims[0].Claim = "o1.severity" },
		"repeated claim":     func(o *Output) { o.Claims[1] = o.Claims[0] },
		"uncited support":    func(o *Output) { o.Claims[0].Citations, o.Claims[0].Evidence = nil, nil },
		"invented citation":  func(o *Output) { o.Claims[0].Citations[0].End = 99 },
		"unknown evidence":   func(o *Output) { o.Claims[0].Evidence = []string{"case-imaginary"} },
		"inconsistent":       func(o *Output) { o.Claims[0].Status = "unresolved" },
		"refuted no refute":  func(o *Output) { o.Decision = "refuted" },
		"unresolved no fact": func(o *Output) { o.Decision = "unresolved"; o.Claims[0].Status = "unresolved" },
		"unresolved+refuted": func(o *Output) {
			o.Decision = "unresolved"
			o.Claims[0].Status = "refuted"
			o.Claims[1].Status = "unresolved"
			o.Unresolved = []string{"x"}
		},
		"label from verifier": func(o *Output) { o.Decision = "confirmed" },
		"uncited control":     func(o *Output) { o.Controls[0].Citations = nil },
		"dropped gap":         func(o *Output) { o.Gaps = nil },
	} {
		o := clone(good)
		change(&o)
		if o.Validate(c) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	raw, _ := json.Marshal(good)
	extra := strings.Replace(string(raw), `"decision":`, `"severity":"high","decision":`, 1)
	if _, err := ParseOutput([]byte(extra), c); err == nil {
		t.Error("extra severity field accepted")
	}
	newCandidate := strings.Replace(string(raw), `"decision":`, `"candidates":[],"decision":`, 1)
	if _, err := ParseOutput([]byte(newCandidate), c); err == nil {
		t.Error("verifier-originated candidate accepted")
	}
}

func TestDecisionRules(t *testing.T) {
	c := testContext()
	sup := supportedOutput(c)
	ref := clone(sup)
	ref.Decision, ref.Claims[0].Status = "refuted", "refuted"
	unr := Offline(c)
	for _, v := range []struct {
		o            Output
		repro, rerun string
		label        string
	}{
		{sup, "reproduced", "reproduced", "confirmed"},
		{sup, "reproduced", "inconclusive", "needs_validation"},
		{sup, "not_reproduced", "not_reproduced", "needs_validation"},
		{sup, "blocked", "reproduced", "needs_validation"},
		{ref, "reproduced", "reproduced", "rejected"},
		{ref, "not_reproduced", "not_reproduced", "rejected"},
		{unr, "reproduced", "reproduced", "needs_validation"},
	} {
		d := Decision{Reproduction: v.repro, Replay: v.rerun}
		decide(&d, v.o)
		if d.Label != v.label || d.Rules != Rules || d.Novelty != "undetermined" {
			t.Errorf("%s/%s/%s: got %s", v.o.Decision, v.repro, v.rerun, d.Label)
		}
		if d.Label == "needs_validation" && (len(d.Unresolved) == 0 || d.Defect != "candidate") {
			t.Errorf("needs_validation without exact unresolved facts: %+v", d)
		}
		if d.Label == "rejected" && (len(d.Refuted) == 0 || d.Defect != "rejected") {
			t.Errorf("rejected without refuted claims: %+v", d)
		}
	}
	d := Decision{Reproduction: "reproduced", Replay: "reproduced"}
	decide(&d, ref)
	if !strings.Contains(d.Reason, "does not restore a refuted premise") {
		t.Error("rejection despite reproduction not explained")
	}
}
