// Package manifest defines Tekmerion's project manifest (the declared target,
// build recipe and scenario; IMPLEMENTATION_PLAN.md section 3) and the run
// manifest that target preparation writes: the verified source revision,
// the build as it ran, the hashes of the built artifact and classpath, the
// source index and the Ariadne bundle's analysis_id.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

// Schema versions.
const (
	ProjectSchema = "tekmerion-project-1"
	RunSchema     = "tekmerion-run-manifest-1"
)

// Network policies of a build.
const (
	NetworkNone    = "none"    // the build runs in an empty network namespace
	NetworkAllowed = "allowed" // the build may use the network; the caller must also allow it
)

// Project is the declared input of a run. Groups of section 3 that later
// phases own (threat model, research scope, budgets) are carried verbatim.
type Project struct {
	SchemaVersion string          `json:"schema_version"`
	Target        Target          `json:"target"`
	Build         Recipe          `json:"build"`
	Scenario      Scenario        `json:"scenario"`
	ThreatModel   json.RawMessage `json:"threat_model,omitempty"`
	ResearchScope json.RawMessage `json:"research_scope,omitempty"`
	Budgets       json.RawMessage `json:"budgets,omitempty"`
}

// Target is the library under research.
type Target struct {
	Repository  string `json:"repository"`            // canonical repository URL
	Revision    string `json:"revision"`              // full commit id
	Coordinates string `json:"coordinates,omitempty"` // group:artifact:version, when published
	// Paths are the parts of the revision exported for the build (all of it
	// when empty).
	Paths []string `json:"paths,omitempty"`
	// SourceRoots tie each source root to the artifact built from it; the
	// source index is built from these pairs.
	SourceRoots []sourceindex.Root `json:"source_roots"`
}

// Recipe is the build. Each step's argv may use ${SRC} (the exported
// source tree, read-only during the build), ${OUT} (the output directory)
// and ${WORK}, and $$ for a literal $; nothing else is expanded and no
// shell is involved unless a step runs one.
type Recipe struct {
	Network string            `json:"network"`
	Env     map[string]string `json:"env,omitempty"`
	Steps   []Step            `json:"steps"`
	Outputs Outputs           `json:"outputs"`
}

// Step is one command.
type Step struct {
	Name string   `json:"name"`
	Argv []string `json:"argv"`
}

// Outputs name the build results, relative to ${OUT}, in the form
// `ariadne research index` takes them.
type Outputs struct {
	App      string `json:"app"`                 // the built library jar (-app)
	Deps     string `json:"deps,omitempty"`      // directory of dependency jars (-deps)
	DepsList string `json:"deps_list,omitempty"` // `mvn dependency:list` style coordinates (-deps-list)
}

// Scenario is the Ariadne indexing scenario.
type Scenario struct {
	Roots   string `json:"roots"`
	Profile string `json:"profile,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

var (
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	envRe    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// reservedEnv are set by the build runner itself.
var reservedEnv = map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "LC_ALL": true, "TZ": true,
	"SOURCE_DATE_EPOCH": true, "JAVA_HOME": true}

// Validate checks a project manifest.
func (p *Project) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if p.SchemaVersion != ProjectSchema {
		bad("schema_version %q, want %q", p.SchemaVersion, ProjectSchema)
	}
	t := p.Target
	if t.Repository == "" {
		bad("target.repository is required")
	}
	if !commitRe.MatchString(t.Revision) {
		bad("target.revision %q must be a full commit id", t.Revision)
	}
	for _, x := range t.Paths {
		if !cleanRel(x) {
			bad("target.paths: %q is not a clean relative path", x)
		}
	}
	if len(t.SourceRoots) == 0 {
		bad("target.source_roots is required")
	}
	for _, r := range t.SourceRoots {
		if !cleanRel(r.Path) || !cleanRel(r.Artifact) {
			bad("target.source_roots: %+v must hold clean relative paths", r)
		}
	}
	b := p.Build
	if b.Network != NetworkNone && b.Network != NetworkAllowed {
		bad("build.network %q, want %q or %q", b.Network, NetworkNone, NetworkAllowed)
	}
	for k := range b.Env {
		if !envRe.MatchString(k) || reservedEnv[k] {
			bad("build.env: %q cannot be set", k)
		}
	}
	if len(b.Steps) == 0 {
		bad("build.steps is empty")
	}
	seen := map[string]bool{}
	for i, s := range b.Steps {
		if !nameRe.MatchString(s.Name) || seen[s.Name] {
			bad("build.steps[%d]: name %q must be unique and match %s", i, s.Name, nameRe)
		}
		seen[s.Name] = true
		if len(s.Argv) == 0 {
			bad("build.steps[%d]: argv is empty", i)
		}
		for _, a := range s.Argv {
			if _, err := Expand(a, map[string]string{"SRC": "", "OUT": "", "WORK": ""}); err != nil {
				bad("build.steps[%d]: %v", i, err)
			}
		}
	}
	o := b.Outputs
	if !cleanRel(o.App) {
		bad("build.outputs.app %q must be a clean relative path", o.App)
	}
	for _, x := range []string{o.Deps, o.DepsList} {
		if x != "" && !cleanRel(x) {
			bad("build.outputs: %q is not a clean relative path", x)
		}
	}
	if o.DepsList != "" && o.Deps == "" {
		bad("build.outputs.deps_list needs build.outputs.deps")
	}
	appRooted := false
	for _, r := range t.SourceRoots {
		appRooted = appRooted || r.Artifact == o.App
	}
	if !appRooted {
		bad("no target.source_roots entry builds build.outputs.app %q", o.App)
	}
	s := p.Scenario
	switch s.Roots {
	case "all", "profile", "api":
	default:
		bad("scenario.roots %q, want all, profile or api", s.Roots)
	}
	if s.Scope != "" && s.Scope != "all" && s.Scope != "reachable" {
		bad("scenario.scope %q, want all or reachable", s.Scope)
	}
	return errors.Join(errs...)
}

// Expand replaces ${SRC}, ${OUT} and ${WORK} in s and $$ with $; any other
// $ is an error.
func Expand(s string, vars map[string]string) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '$')
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		b.WriteString(s[:i])
		s = s[i:]
		if strings.HasPrefix(s, "$$") {
			b.WriteByte('$')
			s = s[2:]
			continue
		}
		j := strings.IndexByte(s, '}')
		if !strings.HasPrefix(s, "${") || j < 0 {
			return "", fmt.Errorf("argument %q: only ${SRC}, ${OUT}, ${WORK} and $$ are expanded", s)
		}
		v, ok := vars[s[2:j]]
		if !ok {
			return "", fmt.Errorf("argument: unknown variable %s", s[:j+1])
		}
		b.WriteString(v)
		s = s[j+1:]
	}
}

func cleanRel(p string) bool {
	return p != "" && !path.IsAbs(p) && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.Contains(p, `\`)
}

// LoadProject reads and validates a project manifest. Unknown fields are
// rejected.
func LoadProject(file string) (*Project, []byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	var p Project
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := p.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	return &p, raw, nil
}

// File is a file and its hash.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Run is the run manifest written by target preparation.
type Run struct {
	SchemaVersion string          `json:"schema_version"`
	PreparedAt    time.Time       `json:"prepared_at"`
	Project       json.RawMessage `json:"project"`        // the project manifest
	ProjectSHA256 string          `json:"project_sha256"` // of the project file's bytes
	Source        Source          `json:"source"`
	Build         Build           `json:"build"`
	Artifacts     Artifacts       `json:"artifacts"`
	SourceIndex   SourceIndex     `json:"source_index"`
	Analysis      *Analysis       `json:"analysis,omitempty"` // absent when no Ariadne binary was given
}

// Source is the verified source revision.
type Source struct {
	Repository     string            `json:"repository"`
	Commit         string            `json:"commit"`
	CommitTime     int64             `json:"commit_time"`
	CheckoutRemote string            `json:"checkout_remote,omitempty"` // origin of the checkout used, informational
	GitTrees       map[string]string `json:"git_trees"`                 // exported path -> git tree/blob id ("." for the whole tree)
	TreeSHA256     string            `json:"tree_sha256"`               // over the exported files: "sha256 mode path" lines
	Files          int               `json:"files"`
}

// Build is the build as it ran.
type Build struct {
	Network            string            `json:"network"`
	NetworkEnforcement string            `json:"network_enforcement"` // "netns" or "none"
	Environment        Environment       `json:"environment"`
	Env                map[string]string `json:"env"` // the step environment except PATH, work directory as ${WORK}
	Steps              []StepRun         `json:"steps"`
}

// Environment identifies where the build ran.
type Environment struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel,omitempty"`
	JavaVersion string `json:"java_version,omitempty"`
	JavaVendor  string `json:"java_vendor,omitempty"`
	JavaVM      string `json:"java_vm,omitempty"`
	JavaHome    string `json:"java_home,omitempty"`
	JavaSHA256  string `json:"java_sha256,omitempty"` // the java launcher on PATH
}

// StepRun is one step's execution.
type StepRun struct {
	Name         string   `json:"name"`
	Argv         []string `json:"argv"` // as executed (network wrapper included), work directory as ${WORK}
	Exit         int      `json:"exit"`
	Duration     string   `json:"duration"`
	StdoutSHA256 string   `json:"stdout_sha256"`
	StderrSHA256 string   `json:"stderr_sha256"`
}

// Artifacts are the build outputs. Classpath is the order Ariadne selects
// in (the app, then dependency jars by file name); ClasspathSHA256 covers
// its "sha256 path" lines.
type Artifacts struct {
	App             File     `json:"app"`
	Deps            []File   `json:"deps"`
	DepsList        *File    `json:"deps_list,omitempty"`
	Classpath       []string `json:"classpath"`
	ClasspathSHA256 string   `json:"classpath_sha256"`
}

// SourceIndex records the saved source index.
type SourceIndex struct {
	File    File `json:"file"`
	Methods int  `json:"methods"`
	Located int  `json:"located"` // methods with a build-verified file
}

// Analysis is the Ariadne bundle built from the artifacts.
type Analysis struct {
	AnalysisID         string   `json:"analysis_id"`
	Bundle             string   `json:"bundle"`
	ManifestSHA256     string   `json:"manifest_sha256"` // this bundle's manifest (it holds created_at, so differs per index run)
	IdentitySHA256     string   `json:"identity_sha256"`
	Roots              string   `json:"roots"`
	Profile            string   `json:"profile,omitempty"`
	Scope              string   `json:"scope"`
	AriadneBinarySHA   string   `json:"ariadne_binary_sha256"`
	AriadneToolVersion string   `json:"ariadne_tool_version"`
	SourcesFlag        bool     `json:"sources_flag"` // -sources was passed
	Argv               []string `json:"argv"`
}

// Save writes the run manifest.
func (r *Run) Save(file string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0o644)
}

// LoadRun reads a run manifest.
func LoadRun(file string) (*Run, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if r.SchemaVersion != RunSchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", file, r.SchemaVersion, RunSchema)
	}
	return &r, nil
}
