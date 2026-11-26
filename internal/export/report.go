// Package export builds the final research report from saved, verified
// state: a versioned report.json, a report.md rendered from the same data,
// and an evidence/ tree of hash-checked artifacts and reproducers. It reads
// ledgers only; it never runs target code or contacts a model.
package export

const (
	ReportSchema = "tekmerion-report-1"
	IndexSchema  = "tekmerion-evidence-index-1"
	ExportSchema = "tekmerion-export-1"
)

type RunRef struct {
	Kind        string `json:"kind"`
	RunID       string `json:"run_id"`
	Status      string `json:"status"`
	Mode        string `json:"mode"`
	SnapshotSHA string `json:"state_snapshot_sha256"`
	Source      string `json:"source"`
}

type Target struct {
	Repository  string `json:"repository"`
	Revision    string `json:"revision"`
	PreparedSHA string `json:"prepared_manifest_sha256"`
	SourceTree  string `json:"source_tree_sha256"`
	App         string `json:"app_sha256"`
	AnalysisID  string `json:"analysis_id"`
}

type Spend struct {
	RunID       string `json:"run_id"`
	Kind        string `json:"kind"`
	Limit       string `json:"limit_usd"`
	Settled     string `json:"settled_usd"`
	Outstanding string `json:"outstanding_usd"`
	Requests    int64  `json:"requests"`
	Tokens      int64  `json:"tokens"`
}

type Costs struct {
	Settled     string  `json:"settled_usd"`
	Outstanding string  `json:"outstanding_usd"`
	Requests    int64   `json:"requests"`
	Runs        []Spend `json:"runs"`
	Note        string  `json:"note"`
}

type Summary struct {
	Candidates     int            `json:"candidates"`
	Labels         map[string]int `json:"labels"`
	Unvalidated    int            `json:"unvalidated"`
	Unexperimented int            `json:"unexperimented"`
	CoverageUnits  int            `json:"coverage_units"`
	Coverage       map[string]int `json:"coverage"`
	Completion     string         `json:"completion"`
}

type Claim struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Verifier string `json:"verifier_status"`
	Note     string `json:"verifier_observation,omitempty"`
}

type Occurrence struct {
	Unit       string `json:"unit_id"`
	Entry      string `json:"api_entry"`
	Static     string `json:"static_execution"`
	Resolution string `json:"resolution,omitempty"`
	Search     string `json:"search,omitempty"`
	Model      string `json:"model,omitempty"`
	Evidence   string `json:"evidence"`
}

type Case struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	Variant   string   `json:"variant"`
	Args      []string `json:"args"`
	Outcome   string   `json:"outcome"`
	Assertion string   `json:"assertion"`
	Escapes   []string `json:"entries_outside_confinement"`
	Exception string   `json:"harness_exception,omitempty"`
	Evidence  string   `json:"evidence"`
}

type Reproduction struct {
	ExperimentRun string   `json:"experiment_run_id"`
	Outcome       string   `json:"outcome"`
	Reason        string   `json:"reason"`
	Cases         []Case   `json:"cases"`
	Reproducer    string   `json:"reproducer"`
	Commands      []string `json:"commands"`
	Harness       string   `json:"harness_sha256"`
	Spec          string   `json:"spec_sha256"`
	Patch         string   `json:"correction_patch_sha256,omitempty"`
	Gaps          []string `json:"gaps"`
}

type Review struct {
	ValidationRun string   `json:"validation_run_id"`
	Mode          string   `json:"mode"`
	Label         string   `json:"label"`
	Verifier      string   `json:"verifier"`
	Replay        string   `json:"fresh_replay"`
	Reason        string   `json:"reason"`
	Rules         string   `json:"rules"`
	Controls      []string `json:"controls"`
	Unresolved    []string `json:"unresolved_facts"`
	Evidence      string   `json:"evidence"`
}

type Finding struct {
	ID           string         `json:"candidate_id"`
	Canonical    string         `json:"canonical"`
	Origin       string         `json:"origin"`
	Label        string         `json:"label"`
	Reason       string         `json:"decision_reason"`
	Defect       string         `json:"defect"`
	Static       string         `json:"static"`
	Reproduction string         `json:"reproduction"`
	Replay       string         `json:"fresh_replay"`
	Novelty      string         `json:"novelty"`
	Property     string         `json:"property"`
	Mechanism    string         `json:"mechanism"`
	RootCause    string         `json:"root_cause"`
	Anchor       string         `json:"root_cause_anchor"`
	Invariant    string         `json:"invariant"`
	Prediction   string         `json:"prediction"`
	Claims       []Claim        `json:"prerequisites"`
	Occurrences  []Occurrence   `json:"occurrences"`
	Experiments  []Reproduction `json:"reproductions"`
	Reviews      []Review       `json:"reviews"`
	Unresolved   []string       `json:"unresolved_facts"`
	Evidence     string         `json:"evidence_dir"`
}

type Unit struct {
	ID      string `json:"unit_id"`
	Initial string `json:"initial"`
	Current string `json:"current"`
	Reason  string `json:"reason"`
}

type Report struct {
	Schema      string    `json:"schema_version"`
	GeneratedAt string    `json:"generated_at"`
	Provenance  string    `json:"provenance"`
	Runs        []RunRef  `json:"runs"`
	Target      Target    `json:"target"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
	Coverage    []Unit    `json:"coverage"`
	Costs       Costs     `json:"costs"`
	Gaps        []string  `json:"gaps"`
	Limits      []string  `json:"limits"`
}
