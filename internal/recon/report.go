package recon

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/state"
)

func Architecture(ctx context.Context, s *state.Store, snap *state.Snapshot) (string, error) {
	raw, err := s.Get(ctx, snap.Run.ManifestSHA)
	if err != nil {
		return "", err
	}
	var m Manifest
	if err := jsonx.Decode(raw, &m, false); err != nil {
		return "", err
	}
	raw, err = s.Get(ctx, m.ContextSHA)
	if err != nil {
		return "", err
	}
	var c Context
	if err := jsonx.Decode(raw, &c, false); err != nil {
		return "", err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "## Recon scope\n\nRepository: %s\n\nRevision: `%s`\n\nPrepared input: `%s`\n\nSource: `%s`\n\nAnalysis: `%s`\n\nSelected API methods: %d; known deferred methods: %d.\n\n", escape(c.Repository), c.Revision, c.PreparedSHA, c.SourceSHA, c.AnalysisID, len(c.Entries), c.DeferredCount)
	b.WriteString("The file-confinement boundary is a catalogue candidate. Recon does not establish attacker authority, a checked invariant or a vulnerability.\n\n")
	var output *Output
	for _, a := range snap.Attempts {
		if a.TaskID == "recon" && a.Outcome == "completed" {
			raw, err := s.Get(ctx, a.ResultSHA)
			if err != nil {
				return "", err
			}
			if m.Mode == "recon-model" {
				var execution gateway.Execution
				if err := jsonx.Decode(raw, &execution, false); err != nil {
					return "", err
				}
				if execution.Result == nil {
					return "", fmt.Errorf("missing saved Recon model output")
				}
				raw = []byte(execution.Result.Content)
			}
			parsed, err := ParseOutput(raw, c)
			if err != nil {
				return "", err
			}
			output = &parsed
		}
	}
	if output == nil {
		b.WriteString("Recon has no accepted architecture output yet.\n\n")
		for _, gap := range c.Gaps {
			fmt.Fprintf(&b, "- %s\n", escape(gap))
		}
	} else {
		fmt.Fprintf(&b, "## Architecture observations\n\n%s\n\n", escape(output.Summary))
		groups := []struct {
			name  string
			facts []Fact
		}{{"Principals", output.Principals}, {"Resources", output.Resources}, {"Inputs", output.Inputs}, {"Transformations", output.Transformations}, {"Controls", output.Controls}, {"Assumptions", output.Assumptions}}
		for _, group := range groups {
			fmt.Fprintf(&b, "### %s\n\n", group.name)
			if len(group.facts) == 0 {
				b.WriteString("No source-grounded observation supplied; this remains unestablished.\n\n")
				continue
			}
			for _, fact := range group.facts {
				fmt.Fprintf(&b, "- %s (%s)", escape(fact.Text), escape(fact.Origin))
				for _, citation := range fact.Citations {
					fmt.Fprintf(&b, " — [%s:%d–%d](artifacts/%s)", escape(citation.Path), citation.Start, citation.End, citation.SHA[7:])
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
		b.WriteString("### Gaps\n\n")
		for _, gap := range output.Gaps {
			fmt.Fprintf(&b, "- %s\n", escape(gap))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Initial coverage\n\n| Stable unit | State | API | Reason | Evidence |\n|---|---|---|---|---|\n")
	for _, unit := range snap.Coverage {
		raw, err := s.Get(ctx, unit.PayloadSHA)
		if err != nil {
			return "", err
		}
		var payload UnitPayload
		if err := jsonx.Decode(raw, &payload, false); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | [unit](artifacts/%s) |\n", unit.ID, unit.Status, escape(methodKey(payload.Entry.Method)), escape(unit.Reason), unit.PayloadSHA[7:])
	}
	b.WriteString("\nThese units are not checked coverage. Unknown/unattempted work remains visible; no vulnerability conclusion is derived from this inventory.\n\n")
	return b.String(), nil
}
func escape(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "\n", " ", "\r", " ", "[", "\\[", "]", "\\]", "!", "\\!", "`", "\\`", "*", "\\*", "_", "\\_").Replace(text)
}
