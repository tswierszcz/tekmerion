package experiment

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tswierszcz/tekmerion/internal/sandbox"
)

func TestSpecValidation(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/experiments/extractor/experiment.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSpec(raw); err != nil {
		t.Fatal(err)
	}
	good, _ := ParseSpec(raw)
	for name, change := range map[string]func(*Spec){
		"no candidate": func(s *Spec) {
			s.Cases = s.Cases[:1]
			s.Cases = append(s.Cases, Case{ID: "n2", Role: "normal", Description: "x"})
		},
		"duplicate case": func(s *Spec) { s.Cases[1].ID = s.Cases[0].ID },
		"unknown role":   func(s *Spec) { s.Cases[0].Role = "exploit" },
		"bad harness":    func(s *Spec) { s.HarnessName = "../x.java" },
		"heap too big":   func(s *Spec) { s.HeapMB = 4096 },
		"zero limit":     func(s *Spec) { s.Limits.Tasks = 0 },
		"NUL argument":   func(s *Spec) { s.Cases[0].Args = []string{"a\x00b"} },
		"property":       func(s *Spec) { s.Property = "rce" },
	} {
		s := good
		s.Cases = append([]Case{}, good.Cases...)
		change(&s)
		if s.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseSpec(append(raw[:len(raw)-2], []byte(`,"extra":1}`)...)); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestObserveNeverFollowsLinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "case")
	outside := filepath.Join(root, "secret")
	os.WriteFile(outside, []byte("host secret"), 0600)
	os.MkdirAll(filepath.Join(dir, "jail", "sub"), 0700)
	os.WriteFile(filepath.Join(dir, "jail", "sub", "a"), []byte("inside"), 0600)
	os.WriteFile(filepath.Join(dir, "escaped"), []byte("payload"), 0600)
	os.Symlink(outside, filepath.Join(dir, "jail", "link"))
	os.Symlink(root, filepath.Join(dir, "dirlink"))
	os.Link(filepath.Join(dir, "escaped"), filepath.Join(dir, "jail", "hard"))
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	promoted := map[string]string{}
	l, err := Observe(dir, func(rel string, b []byte) (string, error) { promoted[rel] = string(b); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]Entry{}
	for _, e := range l.Entries {
		types[e.Path] = e
	}
	if types["jail/link"].Type != "symlink" || types["jail/link"].Link != outside || types["dirlink"].Type != "symlink" || types["fifo"].Type != "fifo" {
		t.Fatalf("links/special files misrecorded: %+v", l.Entries)
	}
	if types["jail/hard"].Links != 2 || types["escaped"].Links != 2 {
		t.Fatalf("hard link not recorded: %+v", types["jail/hard"])
	}
	for _, v := range promoted {
		if v == "host secret" {
			t.Fatal("followed a link out of the worker directory")
		}
	}
	if promoted["jail/sub/a"] != "inside" || promoted["escaped"] != "payload" || len(promoted) != 3 {
		t.Fatalf("promotion: %v", promoted)
	}
	if _, ok := types["dirlink/secret"]; ok {
		t.Fatal("descended through a directory symlink")
	}
}

func TestObserveBoundsEntries(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxEntries+5; i++ {
		os.WriteFile(filepath.Join(dir, strings.Repeat("x", 1+i%50)+string(rune('a'+i%26))+string(rune('a'+i/26))), nil, 0600)
	}
	l, err := Observe(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Truncated || len(l.Entries) != maxEntries {
		t.Fatalf("entries %d truncated %t", len(l.Entries), l.Truncated)
	}
}

func TestClassifyAndAssess(t *testing.T) {
	ok := &HarnessReport{Schema: HarnessSchema, Invoked: "api"}
	exc := &HarnessReport{Schema: HarnessSchema, Invoked: "api", Exception: "java.io.IOException: denied"}
	r := &sandbox.Result{}
	for _, c := range []struct {
		r    sandbox.Result
		h    *HarnessReport
		a    string
		want string
	}{
		{*r, ok, "violated", "property_violated"},
		{*r, ok, "held", "property_held"},
		{*r, exc, "held", "target_exception"},
		{*r, exc, "violated", "property_violated"},
		{sandbox.Result{TimedOut: true}, ok, "violated", "timeout"},
		{sandbox.Result{Signal: "killed"}, ok, "held", "resource_limit"},
		{sandbox.Result{Exit: 1}, ok, "held", "harness_error"},
		{*r, ok, "not_evaluated", "harness_error"},
	} {
		if got, _ := classify(&c.r, c.h, nil, c.a); got != c.want {
			t.Errorf("classify(%+v,%s) = %s, want %s", c.r, c.a, got, c.want)
		}
	}
	if got, _ := classify(r, nil, os.ErrInvalid, "violated"); got != "harness_error" {
		t.Error("unparsable harness report must not count as a violation")
	}
	if _, err := harnessReport([]byte("noise\n{\"schema_version\":\"tekmerion-harness-result-1\",\"invoked\":\"x\",\"exception\":\"\"}\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := harnessReport([]byte(`{"schema_version":"tekmerion-harness-result-1","invoked":"x","exception":"","confirmed":true}`)); err == nil {
		t.Fatal("harness report with extra claims accepted")
	}
	run := func(cases ...CaseSummary) Assessment {
		a := Assessment{Cases: cases}
		assess(&a)
		return a
	}
	n := func(outcome string) CaseSummary { return CaseSummary{CaseID: "n", Role: "normal", Outcome: outcome} }
	c := func(outcome string) CaseSummary { return CaseSummary{CaseID: "c", Role: "candidate", Outcome: outcome} }
	k := func(outcome string) CaseSummary { return CaseSummary{CaseID: "k", Role: "control", Outcome: outcome} }
	for _, v := range []struct {
		a    Assessment
		want string
	}{
		{run(n("property_held"), c("property_violated")), "reproduced"},
		{run(n("property_held"), c("property_violated"), k("property_held")), "reproduced"},
		{run(n("property_held"), c("property_violated"), k("property_violated")), "inconclusive"},
		{run(n("property_violated"), c("property_violated")), "inconclusive"},
		{run(n("property_held"), c("property_held")), "not_reproduced"},
		{run(n("property_held"), c("target_exception")), "inconclusive"},
		{run(n("property_held"), c("timeout")), "inconclusive"},
		{run(n("blocked"), c("blocked")), "blocked"},
		{run(n("invalidated"), c("property_violated")), "inconclusive"},
	} {
		if v.a.Outcome != v.want {
			t.Errorf("%+v: got %s want %s", v.a.Cases, v.a.Outcome, v.want)
		}
	}
	if a := run(n("property_held"), c("property_violated")); !strings.Contains(strings.Join(a.Gaps, "\n"), "no property-preserving control") {
		t.Error("missing control gap not recorded")
	}
}
