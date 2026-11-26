package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/state"
	"github.com/tswierszcz/tekmerion/internal/validate"
)

func Status(ctx context.Context, dir string) (*state.Snapshot, error) {
	s, err := state.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Snapshot(ctx)
}

// Report is a local fixture ledger export, not a vulnerability decision report.
// All bytes and timestamps come from saved state; regeneration uses no model.
func Report(ctx context.Context, dir, format string) ([]byte, error) {
	if format != "json" && format != "markdown" {
		return nil, fmt.Errorf("report format must be json or markdown")
	}
	s, err := state.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	snap, err := s.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Verify(ctx, snap); err != nil {
		return nil, err
	}
	manifestRaw, err := s.Get(ctx, snap.Run.ManifestSHA)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, err
	}
	fixture := m.Schema == FixtureSchema && m.Mode == "fixture"
	model := m.Schema == gateway.RunSchema && m.Mode == "model"
	isRecon := m.Schema == recon.RunSchema && (m.Mode == "recon-offline" || m.Mode == "recon-replay" || m.Mode == "recon-model")
	isHunt := m.Schema == hunt.RunSchema && (m.Mode == "hunt-offline" || m.Mode == "hunt-replay" || m.Mode == "hunt-model")
	isExperiment := m.Schema == experiment.RunSchema && m.Mode == "checked-in-harness"
	isValidate := m.Schema == validate.RunSchema && (m.Mode == "validate-offline" || m.Mode == "validate-replay" || m.Mode == "validate-model")
	if !fixture && !model && !isRecon && !isHunt && !isExperiment && !isValidate {
		return nil, fmt.Errorf("unsupported report manifest")
	}
	if format == "json" {
		raw, err := json.MarshalIndent(snap, "", "  ")
		return append(raw, '\n'), err
	}
	var b bytes.Buffer
	if fixture {
		fmt.Fprintf(&b, "# Tekmerion fixture ledger\n\nRun: `%s`\n\nStatus: **%s**\n\n", snap.Run.ID, snap.Run.Status)
		b.WriteString("Provenance: **fixture**. This run replays static contract examples; it does not investigate a real library or establish vulnerabilities. Paid model requests: **0**.\n\n")
	} else if isValidate {
		fmt.Fprintf(&b, "# Tekmerion validation ledger\n\nRun: `%s`\n\nStatus: **%s**\n\nMode: **%s**.\n\n", snap.Run.ID, snap.Run.Status, m.Mode)
		details, err := validate.Report(ctx, s, snap)
		if err != nil {
			return nil, err
		}
		b.WriteString(details)
	} else if isExperiment {
		fmt.Fprintf(&b, "# Tekmerion experiment ledger\n\nRun: `%s`\n\nStatus: **%s**\n\nMode: **%s**. Paid model requests: **0**.\n\n", snap.Run.ID, snap.Run.Status, m.Mode)
		details, err := experiment.Report(ctx, s, snap)
		if err != nil {
			return nil, err
		}
		b.WriteString(details)
	} else if isHunt {
		fmt.Fprintf(&b, "# Tekmerion Hunt ledger\n\nRun: `%s`\n\nStatus: **%s**\n\nMode: **%s**.\n\n", snap.Run.ID, snap.Run.Status, m.Mode)
		details, err := hunt.Report(ctx, s, snap)
		if err != nil {
			return nil, err
		}
		b.WriteString(details)
	} else if isRecon {
		fmt.Fprintf(&b, "# Tekmerion Recon ledger\n\nRun: `%s`\n\nStatus: **%s**\n\nMode: **%s**.\n\n", snap.Run.ID, snap.Run.Status, m.Mode)
		architecture, err := recon.Architecture(ctx, s, snap)
		if err != nil {
			return nil, err
		}
		b.WriteString(architecture)
	} else {
		fmt.Fprintf(&b, "# Tekmerion model-task ledger\n\nRun: `%s`\n\nStatus: **%s**\n\n", snap.Run.ID, snap.Run.Status)
		b.WriteString("Provenance: **model request**. This is bounded model output and accounting evidence; it is not an independently verified vulnerability finding or a complete research audit.\n\n")
	}
	if budget := snap.Budget; budget != nil {
		fmt.Fprintf(&b, "## Budget (USD)\n\nLimit: %s; settled: %s; outstanding reservations: %s; protected validation: %s; protected reporting: %s; available: %s.\n\nRequests: %d / %d; unsettled requests: %d; tokens accounted: %d / %d; deadline (Unix nanoseconds): %d.\n\n", budget.Config.Limit, budget.Settled, budget.Outstanding, budget.ValidationProtected, budget.ReportingProtected, budget.Available, budget.Requests, budget.Config.MaxRequests, budget.UnsettledRequests, budget.Tokens, budget.Config.MaxTokens, budget.Deadline)
		b.WriteString("| Request | Stage | Model / provider | Reserved USD | Reported USD |\n|---|---|---|---|---|\n")
		for _, r := range budget.Reservations {
			cost := "unknown (reservation retained)"
			if r.Charge != nil {
				cost = r.Charge.String()
			}
			fmt.Fprintf(&b, "| %s | %s | %s / %s | %s | %s |\n", cell(r.ID), cell(r.Stage), cell(r.Model), cell(r.Provider), r.MaxCost, cost)
		}
		for _, u := range budget.Uncertain {
			fmt.Fprintf(&b, "\nUncertain charge observation for %s: %s.\n", cell(u.RequestID), cell(u.Reason))
		}
		for _, halt := range budget.Halts {
			fmt.Fprintf(&b, "\nPaid admission halted for %s: %s.\n", cell(halt.RequestID), cell(halt.Reason))
		}
		b.WriteString("\n")
	}
	if len(snap.Forecasts) > 0 {
		b.WriteString("## Forecast history\n\n")
		for _, f := range snap.Forecasts {
			fmt.Fprintf(&b, "- [Estimate](artifacts/%s), plan `%s`, pricing `%s`.\n", f.ReportSHA[7:], f.PlanSHA, f.PricingSHA)
		}
		latest := snap.Forecasts[len(snap.Forecasts)-1]
		raw, err := s.Get(ctx, latest.ReportSHA)
		if err != nil {
			return nil, err
		}
		var estimate pricing.Estimate
		if err := jsonx.Decode(raw, &estimate, false); err != nil {
			return nil, fmt.Errorf("saved forecast: %w", err)
		}
		if estimate.Schema != pricing.EstimateSchema || estimate.PlanSHA != latest.PlanSHA || estimate.PricingSHA != latest.PricingSHA {
			return nil, fmt.Errorf("saved forecast metadata differs from its evidence links")
		}
		if estimate.Plan.TargetIdentity != snap.Run.ManifestSHA {
			b.WriteString("\nLatest forecast target differs from this run; no cost comparison is made.\n\n")
		} else if snap.Budget != nil {
			b.WriteString("\nLatest forecast versus observed accounting (USD). Scenario assumptions remain in its saved plan; outstanding amounts are conservative ceilings.\n\n| Stage | Model / provider | Forecast base | Finite bound | Settled | Outstanding |\n|---|---|---|---|---|---|\n")
			value := func(m *state.Money) string {
				if m == nil {
					return "unavailable"
				}
				return m.String()
			}
			for _, role := range estimate.Roles {
				settled, outstanding := state.Money(0), state.Money(0)
				for _, r := range snap.Budget.Reservations {
					if r.Stage == role.Role.Stage && r.Model == role.Role.Model && r.Provider == role.Role.Provider {
						if r.Charge != nil {
							settled += *r.Charge
						} else {
							outstanding += r.MaxCost
						}
					}
				}
				fmt.Fprintf(&b, "| %s | %s / %s | %s | %s | %s | %s |\n", cell(role.Role.Stage), cell(role.Role.Model), cell(role.Role.Provider), value(role.Forecast.Base), value(role.Maximum), settled, outstanding)
			}
			b.WriteString("\nActual requests on routes absent from the estimate remain in the budget reservation ledger above.\n\n")
		}
	}
	b.WriteString("## Tasks\n\n| Task | Operation | Status |\n|---|---|---|\n")
	for _, task := range snap.Tasks {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(task.ID), cell(task.Stage), cell(task.Status))
	}
	b.WriteString("\n## Attempts\n\n| Task | Attempt | Outcome | Evidence | Diagnostic |\n|---|---|---|---|---|\n")
	for _, a := range snap.Attempts {
		evidence := "—"
		if a.ResultSHA != "" {
			evidence = fmt.Sprintf("[result](artifacts/%s)", a.ResultSHA[7:])
		}
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s |\n", cell(a.TaskID), a.Number, cell(a.Outcome), evidence, cell(a.Diagnostic))
	}
	b.WriteString("\n## Evidence\n\n")
	for _, a := range snap.Artifacts {
		fmt.Fprintf(&b, "- [%s](artifacts/%s), %d bytes, %s\n", a.SHA, a.SHA[7:], a.Size, cell(a.MediaType))
	}
	b.WriteString("\nPending/running tasks and interrupted attempts remain visible above. Full Recon/Hunt workflows, independent verification and final research exports are not implemented in this ledger.\n")
	return b.Bytes(), nil
}
func cell(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "\n", " ", "\r", " ", "`", "&#96;")
	return r.Replace(s)
}
