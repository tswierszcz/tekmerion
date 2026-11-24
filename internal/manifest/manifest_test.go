package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlProjectValid(t *testing.T) {
	p, raw, err := LoadProject("../../testdata/control/project.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || p.Build.Network != NetworkNone || p.Build.Outputs.App != "lib.jar" {
		t.Fatalf("%+v", p)
	}
}

func TestValidateRejects(t *testing.T) {
	base, _, err := LoadProject("../../testdata/control/project.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *Project){
		"short revision":   func(p *Project) { p.Target.Revision = "baf3384" },
		"network":          func(p *Project) { p.Build.Network = "maybe" },
		"escaping path":    func(p *Project) { p.Target.Paths = []string{"../etc"} },
		"absolute output":  func(p *Project) { p.Build.Outputs.App = "/tmp/lib.jar" },
		"unrooted app":     func(p *Project) { p.Build.Outputs.App = "other.jar" },
		"reserved env":     func(p *Project) { p.Build.Env = map[string]string{"PATH": "/x"} },
		"unknown variable": func(p *Project) { p.Build.Steps[0].Argv = []string{"echo", "${HOME}"} },
		"bare dollar":      func(p *Project) { p.Build.Steps[0].Argv = []string{"echo", "$OUT"} },
		"duplicate step":   func(p *Project) { p.Build.Steps[1].Name = p.Build.Steps[0].Name },
		"roots":            func(p *Project) { p.Scenario.Roots = "" },
		"deps list alone":  func(p *Project) { p.Build.Outputs.Deps = "" },
	}
	for name, mut := range cases {
		p := *base
		p.Build.Steps = append([]Step(nil), base.Build.Steps...)
		mut(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadProjectUnknownField(t *testing.T) {
	raw, _ := os.ReadFile("../../testdata/control/project.json")
	f := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(f, []byte(strings.Replace(string(raw), `"scenario"`, `"extra": 1, "scenario"`, 1)), 0o644)
	if _, _, err := LoadProject(f); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]string{"SRC": "/s", "OUT": "/o", "WORK": "/w"}
	for in, want := range map[string]string{
		"${OUT}/lib.jar": "/o/lib.jar", "a${SRC}b${WORK}": "a/sb/w", "$$1": "$1", "plain": "plain",
	} {
		got, err := Expand(in, vars)
		if err != nil || got != want {
			t.Errorf("Expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"$OUT", "${OUT", "${PATH}", "$"} {
		if _, err := Expand(in, vars); err == nil {
			t.Errorf("Expand(%q) accepted", in)
		}
	}
}
