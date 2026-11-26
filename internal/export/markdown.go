package export

import (
	"fmt"
	"strings"
)

func cell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'").Replace(s)
}

// sentence ends a saved reason with a period so it reads as prose.
func sentence(s string) string {
	s = cell(strings.TrimSpace(s))
	if s != "" && !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func linkTo(text, rel string) string {
	if rel == "" {
		return cell(text)
	}
	return "[" + cell(text) + "](" + rel + ")"
}

// Markdown renders report.md from the same Report as report.json, so the two
// cannot disagree. It adds no facts of its own.
func Markdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Tekmerion research report\n\nSchema `%s`; generated %s; provenance **%s**.\n\n", r.Schema, r.GeneratedAt, r.Provenance)
	t := r.Target
	fmt.Fprintf(&b, "Target: %s at `%s`. Source tree `%s`; app `%s`; analysis `%s`; prepared manifest `%s`.\n\n", cell(t.Repository), t.Revision, t.SourceTree, t.App, t.AnalysisID, t.PreparedSHA)

	s := r.Summary
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "Candidates: **%d** — confirmed **%d**, needs validation **%d**, rejected **%d**. Without an experiment: %d; without independent validation: %d.\n\n", s.Candidates, s.Labels["confirmed"], s.Labels["needs_validation"], s.Labels["rejected"], s.Unexperimented, s.Unvalidated)
	fmt.Fprintf(&b, "Coverage units: %d (%s).\n\n", s.CoverageUnits, counts(s.Coverage))
	fmt.Fprintf(&b, "LLM spend: **%s USD** settled, %s USD outstanding, %d requests. Completion: %s.\n\n", r.Costs.Settled, r.Costs.Outstanding, r.Costs.Requests, cell(s.Completion))

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "## Finding %s — %s\n\n", short(f.ID), f.Label)
		fmt.Fprintf(&b, "Candidate `%s`; origin %s; property %s.\n\n", f.ID, f.Origin, f.Property)
		fmt.Fprintf(&b, "Decision: **%s**. %s\n\n", f.Label, sentence(f.Reason))
		fmt.Fprintf(&b, "Axes: defect **%s**; reproduction **%s**; fresh replay **%s**; novelty **%s**. Static: %s.\n\n", f.Defect, f.Reproduction, f.Replay, f.Novelty, cell(f.Static))
		fmt.Fprintf(&b, "Root cause: `%s`, anchor `%s`. Mechanism: %s. Invariant: %s. Prediction: %s.\n\n", cell(f.RootCause), cell(f.Anchor), cell(f.Mechanism), cell(f.Invariant), cell(f.Prediction))
		b.WriteString("| Prerequisite | Claim | Verifier |\n|---|---|---|\n")
		for _, c := range f.Claims {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", c.ID, cell(c.Text), c.Verifier)
		}
		b.WriteString("\n| API entry | Unit | Static | Resolution / search / model | Evidence |\n|---|---|---|---|---|\n")
		for _, o := range f.Occurrences {
			fmt.Fprintf(&b, "| %s | %s | %s | %s / %s / %s | %s |\n", cell(o.Entry), short(o.Unit), o.Static, o.Resolution, o.Search, o.Model, linkTo("occurrence", o.Evidence))
		}
		for _, e := range f.Experiments {
			fmt.Fprintf(&b, "\n### Reproduction (experiment %s): %s\n\n%s Reproducer: [%s](%s/README.md).\n\n| Case | Role | Variant | Outcome | Assertion | Outside confinement | Evidence |\n|---|---|---|---|---|---|---|\n", e.ExperimentRun, e.Outcome, sentence(e.Reason), e.Reproducer, e.Reproducer)
			for _, c := range e.Cases {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", c.ID, c.Role, c.Variant, c.Outcome, c.Assertion, cell(strings.Join(c.Escapes, ", ")), linkTo("observation", c.Evidence))
			}
		}
		for _, v := range f.Reviews {
			fmt.Fprintf(&b, "\n### Review (validation %s, %s)\n\nVerifier **%s**; fresh replay **%s**; label **%s** (rules `%s`). %s %s\n\n", v.ValidationRun, v.Mode, v.Verifier, v.Replay, v.Label, v.Rules, sentence(v.Reason), linkTo("decision", v.Evidence))
			for _, c := range v.Controls {
				fmt.Fprintf(&b, "- Control: %s\n", cell(c))
			}
		}
		if len(f.Unresolved) > 0 {
			b.WriteString("\nUnresolved facts:\n\n")
			for _, u := range f.Unresolved {
				fmt.Fprintf(&b, "- %s\n", cell(u))
			}
		}
		b.WriteString("\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("## Findings\n\nNo candidate was generated in the investigated scope.\n\n")
	}

	b.WriteString("## Coverage\n\n| Unit | Initial | Current | Reason |\n|---|---|---|---|\n")
	for _, u := range r.Coverage {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", short(u.ID), u.Initial, u.Current, cell(u.Reason))
	}
	b.WriteString("\n## Costs\n\n| Run | Kind | Limit USD | Settled USD | Outstanding USD | Requests | Tokens |\n|---|---|---|---|---|---|---|\n")
	for _, c := range r.Costs.Runs {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d | %d |\n", c.RunID, c.Kind, c.Limit, c.Settled, c.Outstanding, c.Requests, c.Tokens)
	}
	fmt.Fprintf(&b, "\n%s\n\n## Runs\n\n| Kind | Run | Status | Mode | Snapshot | Source |\n|---|---|---|---|---|---|\n", cell(r.Costs.Note))
	for _, run := range r.Runs {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | `%s` | %s |\n", run.Kind, run.RunID, run.Status, run.Mode, run.SnapshotSHA, cell(run.Source))
	}
	b.WriteString("\n## Gaps\n\n")
	for _, g := range r.Gaps {
		fmt.Fprintf(&b, "- %s\n", cell(g))
	}
	b.WriteString("\n## Limits\n\n")
	for _, l := range r.Limits {
		fmt.Fprintf(&b, "- %s\n", cell(l))
	}
	b.WriteString("\nEvidence: [index](evidence/index.json). Every artifact is stored under its SHA-256 and was verified before this export was marked complete.\n")
	return b.String()
}

func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func counts(m map[string]int) string {
	order := []string{"planned", "checked", "candidate", "blocked", "deferred", "out_of_scope"}
	parts := []string{}
	for _, k := range order {
		if m[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
		}
	}
	return strings.Join(parts, ", ")
}
