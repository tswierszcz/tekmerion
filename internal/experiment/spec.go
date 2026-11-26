// Package experiment runs a checked-in harness against the original pinned
// library through its public API, in a bounded sandbox, and records a
// reproduction assessment for one Hunt candidate. The security assertion is
// evaluated by trusted host code on the terminated worker's filesystem, not by
// the harness or the target.
package experiment

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/sandbox"
)

const (
	SpecSchema    = "tekmerion-experiment-1"
	RunSchema     = "tekmerion-experiment-run-1"
	HarnessSchema = "tekmerion-harness-result-1"
	CaseSchema    = "tekmerion-experiment-case-1"
	AssessSchema  = "tekmerion-reproduction-1"
	Property      = "file-confinement-1"
)

// Spec declares one deterministic experiment. Every case runs the same
// harness in a fresh worker; the first harness argument is always the
// confinement directory, followed by the case arguments.
type Spec struct {
	Schema      string         `json:"schema_version"`
	Property    string         `json:"property"`
	HarnessName string         `json:"harness_name"`
	Harness     string         `json:"harness"`
	HeapMB      int64          `json:"heap_mb"`
	Limits      sandbox.Limits `json:"limits"`
	Cases       []Case         `json:"cases"`
}

// Case roles: normal input, the candidate's input, and an optional
// property-preserving control.
type Case struct {
	ID          string   `json:"id"`
	Role        string   `json:"role"`
	Description string   `json:"description"`
	Args        []string `json:"args"`
}

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	harnessPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9_]{0,63}\.java$`)
)

func ParseSpec(raw []byte) (Spec, error) {
	var s Spec
	if err := jsonx.Decode(raw, &s, false); err != nil {
		return s, err
	}
	return s, s.Validate()
}

func (s Spec) Validate() error {
	if s.Schema != SpecSchema || s.Property != Property {
		return fmt.Errorf("experiment spec must be %s for property %s", SpecSchema, Property)
	}
	if !harnessPattern.MatchString(s.HarnessName) || s.Harness == "" {
		return fmt.Errorf("harness_name must be a Java source file name such as Harness.java, and harness its path")
	}
	if err := s.Limits.Validate(); err != nil {
		return err
	}
	if s.HeapMB < 16 || s.HeapMB*2<<20 > s.Limits.MemoryBytes {
		return fmt.Errorf("heap_mb must be at least 16 and at most half of the memory limit")
	}
	if len(s.Cases) < 2 || len(s.Cases) > 16 {
		return fmt.Errorf("experiment needs 2..16 cases")
	}
	seen, roles := map[string]bool{}, map[string]int{}
	for _, c := range s.Cases {
		if !idPattern.MatchString(c.ID) || seen[c.ID] {
			return fmt.Errorf("invalid or duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		switch c.Role {
		case "normal", "candidate", "control":
		default:
			return fmt.Errorf("case %s: role must be normal, candidate or control", c.ID)
		}
		roles[c.Role]++
		if c.Description == "" || len(c.Description) > 1000 || len(c.Args) > 16 {
			return fmt.Errorf("case %s needs a description and at most 16 arguments", c.ID)
		}
		for _, a := range c.Args {
			if len(a) > 4096 || !utf8.ValidString(a) {
				return fmt.Errorf("case %s: arguments must be UTF-8 and at most 4096 bytes", c.ID)
			}
			for _, r := range a {
				if r == 0 {
					return fmt.Errorf("case %s: NUL in argument", c.ID)
				}
			}
		}
	}
	if roles["normal"] == 0 || roles["candidate"] == 0 {
		return fmt.Errorf("experiment needs at least one normal and one candidate case")
	}
	return nil
}
