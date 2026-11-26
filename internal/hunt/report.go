package hunt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/state"
)

func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "\\|", "\n", " ", "\r", " ", "`", "&#96;", "[", "&#91;", "]", "&#93;", "*", "&#42;", "_", "&#95;")
	return r.Replace(s)
}
func Report(ctx context.Context, s *state.Store, snap *state.Snapshot) (string, error) {
	var m Manifest
	if err := decode(ctx, s, snap.Run.ManifestSHA, &m); err != nil {
		return "", err
	}
	var parent state.Snapshot
	if err := decode(ctx, s, m.ParentSHA, &parent); err != nil {
		return "", err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "## Hunt scope\n\nParent Recon: `%s` ([saved ledger](artifacts/%s)). Its spend is separate from this explicitly derived run.\n\nPrepared input: `%s`. Tasks selected: %d; planned units outside this wave: %d.\n\n", escape(m.ParentRunID), m.ParentSHA[7:], m.PreparedSHA, len(m.Jobs), len(m.DeferredUnits))
	if parent.Budget != nil {
		fmt.Fprintf(&b, "Parent spend: %s USD settled; %s USD outstanding.\n\n", parent.Budget.Settled, parent.Budget.Outstanding)
	}
	b.WriteString("All hypotheses remain **candidate**; reproduction **not_run**, novelty **undetermined**. Static resolution, search and model scope are independent. A found path does not confirm a defect; a missing path does not refute one. Checked units mean a bounded source review, not proof of safety.\n\n")
	b.WriteString("## Coverage\n\n| Unit | Initial | Current | Reason |\n|---|---|---|---|\n")
	events := map[string]state.CoverageEvent{}
	for _, e := range snap.CoverageHistory {
		events[e.UnitID] = e
	}
	outside := map[string]bool{}
	for _, id := range m.DeferredUnits {
		outside[id] = true
	}
	for _, u := range snap.Coverage {
		status, reason := u.Status, u.Reason
		if e, ok := events[u.ID]; ok {
			status, reason = e.Status, e.Reason
		} else if outside[u.ID] {
			status, reason = "deferred", "outside max-units for this wave"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", u.ID, u.Status, status, escape(reason))
	}
	fmt.Fprintf(&b, "\n## Candidate hypotheses\n\nExact root causes: %d; entry occurrences: %d.\n\n", len(snap.Candidates), len(snap.Occurrences))
	for _, row := range snap.Occurrences {
		var o Occurrence
		if err := decode(ctx, s, row.PayloadSHA, &o); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "### %s\n\nUnit: `%s`; [complete occurrence](artifacts/%s); [source](artifacts/%s), %s:%d–%d.\n\n", o.CandidateID, o.UnitID, row.PayloadSHA[7:], o.Hypothesis.RootCause.SHA[7:], escape(o.Hypothesis.RootCause.Path), o.Hypothesis.RootCause.Start, o.Hypothesis.RootCause.End)
		v := o.Hypothesis
		for _, f := range []struct{ name, value string }{{"Invariant", v.Invariant}, {"Mechanism", v.Mechanism}, {"Principal (" + v.Principal.Origin + ")", v.Principal.Text}, {"Resource (" + v.Resource.Origin + ")", v.Resource.Text}, {"Controlled input (" + v.ControlledInput.Origin + ")", v.ControlledInput.Text}, {"Prediction", v.Prediction}, {"Proposed experiment", v.Experiment}, {"Existing controls", v.Controls}, {"Counterarguments", v.Counterarguments}} {
			fmt.Fprintf(&b, "%s: %s\n\n", escape(f.name), escape(f.value))
		}
		for _, f := range v.Conditions {
			fmt.Fprintf(&b, "Condition (%s): %s\n\n", escape(f.Origin), escape(f.Text))
		}
		fmt.Fprintf(&b, "Static execution: **%s**; provenance: %s; validation: %s. %s\n\n", escape(o.Static.Execution), escape(o.Static.Provenance), escape(o.Static.ValidationScope), escape(o.Static.Diagnostic))
		if len(o.Static.Result) > 0 {
			var axes struct {
				Resolution string `json:"resolution"`
				Search     struct {
					State string `json:"state"`
				} `json:"search"`
				Model struct {
					State string   `json:"state"`
					Gaps  []string `json:"relevant_gap_ids"`
				} `json:"model"`
			}
			if err := json.Unmarshal(o.Static.Result, &axes); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "Resolution: %s; search: %s; model: %s; relevant gaps: %s. [Full response and path evidence](artifacts/%s).\n\n", escape(axes.Resolution), escape(axes.Search.State), escape(axes.Model.State), escape(strings.Join(axes.Model.Gaps, ", ")), o.Static.ResponseSHA[7:])
		}
	}
	b.WriteString("## Review evidence and remaining gaps\n\n")
	for _, job := range m.Jobs {
		var c Context
		if err := decode(ctx, s, job.ContextSHA, &c); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "### %s\n\n[Saved bounded context](artifacts/%s).\n\n", job.TaskID, job.ContextSHA[7:])
		for _, g := range c.Gaps {
			fmt.Fprintf(&b, "- %s\n", escape(g))
		}
		b.WriteString("\n")
		task, err := taskByID(snap, job.TaskID)
		if err != nil {
			return "", err
		}
		if task.Status == "completed" {
			raw, err := completedRaw(ctx, s, snap, task)
			if err != nil {
				return "", err
			}
			o, err := ParseOutput(raw, c)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "Conclusion: %s. %s\n\n", escape(o.Conclusion), escape(o.Reason))
			for _, check := range o.Checks {
				fmt.Fprintf(&b, "- %s (%s): %s\n", escape(check.Invariant), escape(check.Method), escape(check.Observation))
			}
			for _, g := range o.Gaps {
				fmt.Fprintf(&b, "- %s\n", escape(g))
			}
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}
