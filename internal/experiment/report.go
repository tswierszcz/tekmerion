package experiment

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/sandbox"
	"github.com/tswierszcz/tekmerion/internal/state"
)

func cell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'").Replace(s)
}

func link(sha string) string { return "artifacts/" + strings.TrimPrefix(sha, "sha256:") }

// Report renders saved experiment state. It reads only the ledger.
func Report(ctx context.Context, s *state.Store, snap *state.Snapshot) (string, error) {
	var m Manifest
	if err := decode(ctx, s, snap.Run.ManifestSHA, &m); err != nil {
		return "", err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "## Experiment scope\n\nCandidate: `%s` (`%s`). Parent Hunt: `%s` ([saved ledger](%s)).\n\n", m.CandidateID, cell(m.CandidateCanonical), m.ParentRunID, link(m.ParentSHA))
	for _, sha := range m.OccurrenceSHAs {
		fmt.Fprintf(&b, "- [Candidate occurrence](%s)\n", link(sha))
	}
	fmt.Fprintf(&b, "\nPrepared input: `%s`. [Spec](%s); [harness %s](%s) (checked in, %s).\n\n", m.PreparedSHA, link(m.SpecSHA), cell(m.HarnessName), link(m.HarnessSHA), m.Mode)
	if sha, ok := completed(snap, "capabilities"); ok {
		var c sandbox.Capabilities
		if err := decode(ctx, s, sha, &c); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "## Sandbox capabilities\n\nEstablished: **%t**. [Probe record](%s).\n\n| Check | Expected | Observed | OK |\n|---|---|---|---|\n", c.OK, link(sha))
		for _, v := range c.Checks {
			fmt.Fprintf(&b, "| %s | %s | %s | %t |\n", cell(v.Name), cell(v.Expected), cell(v.Observed), v.OK)
		}
		if c.Error != "" {
			fmt.Fprintf(&b, "\nProbe error: %s\n", cell(c.Error))
		}
		b.WriteString("\n")
	}
	if m.PatchSHA != "" {
		fmt.Fprintf(&b, "## Corrected variant\n\n[Correction patch](%s), applied to a separate copy of the same revision and built with the project recipe.\n\n", link(m.PatchSHA))
		if sha, ok := completed(snap, "correction"); ok {
			var rec VariantRecord
			if err := decode(ctx, s, sha, &rec); err != nil {
				return "", err
			}
			if rec.Variant == nil {
				fmt.Fprintf(&b, "Not available: %s. [Record](%s).\n\n", cell(rec.Error), link(sha))
			} else {
				fmt.Fprintf(&b, "Corrected tree `%s` (base `%s`); app `%s`; classpath `%s`. [Record](%s).\n\n| Changed file | Before | After |\n|---|---|---|\n", rec.Variant.TreeSHA256, rec.Variant.BaseTreeSHA256, rec.Variant.Artifacts.App.SHA256, rec.Variant.Artifacts.ClasspathSHA256, link(sha))
				for _, f := range rec.Variant.Changed {
					after := f.After
					if a, ok := rec.Sources[f.Path]; ok {
						after = fmt.Sprintf("[%s](%s)", a, link(a))
					}
					fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(f.Path), cell(f.Before), after)
				}
				b.WriteString("\n")
			}
		} else {
			b.WriteString("Not built yet.\n\n")
		}
	}
	b.WriteString("## Cases\n\n| Case | Role | Variant | Outcome | Assertion | Outside confinement | Reason | Evidence |\n|---|---|---|---|---|---|---|---|\n")
	for _, job := range m.Cases {
		sha, ok := completed(snap, job.TaskID)
		if !ok {
			fmt.Fprintf(&b, "| %s | | | not run | | | | |\n", job.TaskID)
			continue
		}
		var o Observation
		if err := decode(ctx, s, sha, &o); err != nil {
			return "", err
		}
		evidence := fmt.Sprintf("[observation](%s)", link(sha))
		if o.SandboxSHA != "" {
			evidence += fmt.Sprintf(", [worker](%s)", link(o.SandboxSHA))
		}
		fmt.Fprintf(&b, "| %s | %s | %s | **%s** | %s | %s | %s | %s |\n", o.Case.ID, o.Case.Role, o.Case.VariantName(), o.Outcome, o.Assertion, cell(strings.Join(o.Escapes, ", ")), cell(o.Reason), evidence)
	}
	b.WriteString("\n## Reproduction\n\n")
	if len(snap.Reproductions) == 0 {
		b.WriteString("Not assessed yet.\n\n")
		return b.String(), nil
	}
	for _, r := range snap.Reproductions {
		var a Assessment
		if err := decode(ctx, s, r.PayloadSHA, &a); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "Reproduction: **%s**. %s\n\nDefect: **%s**; novelty: **%s**. A reproduced effect is one input to independent verification, not a confirmed finding. [Assessment](%s).\n\n", a.Outcome, cell(a.Reason), a.Defect, a.Novelty, link(r.PayloadSHA))
		b.WriteString("Limits of this result:\n\n")
		for _, g := range a.Gaps {
			fmt.Fprintf(&b, "- %s\n", cell(g))
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
