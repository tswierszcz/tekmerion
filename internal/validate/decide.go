package validate

import (
	"strings"
)

// Decision is the versioned mapping from independent axes to a report label.
type Decision struct {
	Schema          string   `json:"schema_version"`
	Rules           string   `json:"rules"`
	CandidateID     string   `json:"candidate_id"`
	Label           string   `json:"label"`
	Reason          string   `json:"reason"`
	Verifier        string   `json:"verifier"`
	VerifierReason  string   `json:"verifier_reason"`
	Refuted         []string `json:"refuted_claims"`
	Unresolved      []string `json:"unresolved_facts"`
	Reproduction    string   `json:"reproduction"`
	Replay          string   `json:"fresh_replay"`
	Defect          string   `json:"defect"`
	Novelty         string   `json:"novelty"`
	OutputSHA       string   `json:"verifier_output_sha256"`
	ReplaySHA       string   `json:"replay_sha256"`
	ExperimentRunID string   `json:"experiment_run_id"`
}

// decide applies tekmerion-decision-rules-1:
//
//  1. A verifier refutation of any claim rejects the candidate, whatever the
//     experiment showed: an observed effect does not restore a refuted premise
//     such as caller control.
//  2. Confirmation needs every claim supported by the verifier, a reproduced
//     effect in the recorded experiment and the same result in a fresh-worker
//     replay.
//  3. Everything else needs validation, with each missing fact named.
//
// Defect follows the label; novelty is never decided here.
func decide(d *Decision, o Output) {
	d.Rules, d.Verifier, d.VerifierReason, d.Novelty = Rules, o.Decision, o.Reason, "undetermined"
	d.Refuted, d.Unresolved = []string{}, append([]string{}, o.Unresolved...)
	for _, a := range o.Claims {
		if a.Status == "refuted" {
			d.Refuted = append(d.Refuted, a.Claim)
		}
	}
	switch {
	case o.Decision == "refuted":
		d.Label, d.Defect = "rejected", "rejected"
		d.Reason = "the independent verifier refuted: " + strings.Join(d.Refuted, ", ")
		if d.Reproduction == "reproduced" {
			d.Reason += "; the reproduced effect does not restore a refuted premise"
		}
	case o.Decision == "supported" && d.Reproduction == "reproduced" && d.Replay == "reproduced":
		d.Label, d.Defect = "confirmed", "confirmed"
		d.Reason = "every claim was supported by the independent verifier and the effect was reproduced in the recorded experiment and in a fresh-worker replay"
	default:
		d.Label, d.Defect = "needs_validation", "candidate"
		if d.Reproduction != "reproduced" {
			d.Unresolved = append(d.Unresolved, "recorded reproduction is "+d.Reproduction)
		}
		if d.Replay != "reproduced" {
			d.Unresolved = append(d.Unresolved, "fresh-worker replay is "+d.Replay)
		}
		d.Reason = "verifier decision " + o.Decision + "; unresolved: " + strings.Join(d.Unresolved, "; ")
	}
}
