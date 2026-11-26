package validate

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/state"
)

func cell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'").Replace(s)
}

func link(sha string) string { return "artifacts/" + strings.TrimPrefix(sha, "sha256:") }

// Report renders saved validation state without contacting a model.
func Report(ctx context.Context, s *state.Store, snap *state.Snapshot) (string, error) {
	var m Manifest
	if err := decode(ctx, s, snap.Run.ManifestSHA, &m); err != nil {
		return "", err
	}
	var c Context
	if err := decode(ctx, s, m.ContextSHA, &c); err != nil {
		return "", err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "## Validation scope\n\nCandidate: `%s` (`%s`). Parent experiment: `%s` ([saved ledger](%s)).\n\n", c.CandidateID, cell(c.Canonical), m.ParentRunID, link(m.ParentSHA))
	fmt.Fprintf(&b, "Verifier context: [`%s`](%s); prompt %s ([text](%s), [instruction provenance](%s)); decision rules `%s`. The verifier did not see Hunt's reasoning beyond the claims it must assess, and no other verifier's conclusion.\n\n", c.Identity, link(m.ContextSHA), PromptRevision, link(m.PromptSHA), link(m.InstructionsSHA), m.Rules)
	if sha, ok := experiment.Completed(snap, "replay"); ok {
		var r experiment.ReplayResult
		if err := decode(ctx, s, sha, &r); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "## Fresh-worker replay\n\nReplay: **%s** (recorded experiment: **%s**). [Replay record](%s); [capabilities](%s).\n\n| Case | Role | Variant | Outcome | Assertion |\n|---|---|---|---|---|\n", r.Assessment.Outcome, c.Experiment.Reproduction, link(sha), link(r.CapabilitiesSHA))
		for _, v := range r.Cases {
			fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s | %s |\n", v.CaseID, link(v.ObservationSHA), v.Role, v.Variant, v.Outcome, v.Assertion)
		}
		b.WriteString("\n")
	}
	vt, err := task(snap, "validate")
	if err != nil {
		return "", err
	}
	if sha, ok := experiment.Completed(snap, "validate"); ok {
		raw, _, err := verifierRaw(ctx, s, vt, sha)
		if err != nil {
			return "", err
		}
		o, err := ParseOutput(raw, c)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "## Independent verifier\n\nMode: %s. Decision: **%s**. %s [Output](%s).\n\n| Claim | Proposed | Status | Observation | Evidence |\n|---|---|---|---|---|\n", m.Mode, o.Decision, cell(o.Reason), link(sha))
		text := map[string]string{}
		for _, cl := range c.Claims {
			text[cl.ID] = cl.Text
		}
		for _, a := range o.Claims {
			refs := append([]string{}, a.Evidence...)
			for _, q := range a.Citations {
				refs = append(refs, fmt.Sprintf("%s:%d–%d", q.Path, q.Start, q.End))
			}
			fmt.Fprintf(&b, "| %s | %s | **%s** | %s | %s |\n", a.Claim, cell(text[a.Claim]), a.Status, cell(a.Observation), cell(strings.Join(refs, ", ")))
		}
		if len(o.Controls) > 0 {
			b.WriteString("\nStrongest controls reconstructed:\n\n")
			for _, v := range o.Controls {
				fmt.Fprintf(&b, "- %s\n", cell(v.Text))
			}
		}
		b.WriteString("\n")
	} else if vt.Status == "failed" {
		b.WriteString("## Independent verifier\n\nFailed; see the attempt diagnostics in the JSON report.\n\n")
	}
	b.WriteString("## Decision\n\n")
	if len(snap.Decisions) == 0 {
		b.WriteString("Not decided yet.\n\n")
		return b.String(), nil
	}
	for _, row := range snap.Decisions {
		var d Decision
		if err := decode(ctx, s, row.PayloadSHA, &d); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "Label: **%s** (rules `%s`). %s\n\nAxes: verifier **%s**; recorded reproduction **%s**; fresh replay **%s**; defect **%s**; novelty **%s**. [Decision record](%s).\n\n", d.Label, d.Rules, cell(d.Reason), d.Verifier, d.Reproduction, d.Replay, d.Defect, d.Novelty, link(row.PayloadSHA))
		if len(d.Unresolved) > 0 {
			b.WriteString("Unresolved facts:\n\n")
			for _, u := range d.Unresolved {
				fmt.Fprintf(&b, "- %s\n", cell(u))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("Limits of this result:\n\n")
	for _, g := range c.Gaps {
		fmt.Fprintf(&b, "- %s\n", cell(g))
	}
	b.WriteString("\nA confirmed label means the claims held under independent review and the effect was reproduced twice within the stated scope. It does not establish novelty, severity or that a CVE exists.\n\n")
	return b.String(), nil
}
