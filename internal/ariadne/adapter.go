package ariadne

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// Provenance kinds a Result can carry.
const (
	ProvenanceAnalysis = "analysis" // answered by the real Ariadne binary
	ProvenanceFixture  = "fixture"  // replayed from a recorded contract fixture
)

// Outcomes of one attempt, as recorded in attempt.json.
const (
	OutcomeResult         = "result"          // exit 0, ok response, correlated
	OutcomeInvalidRequest = "invalid_request" // exit 2, error response
	OutcomeFailure        = "failure"         // exit 1, error response (bundle, I/O, internal)
	OutcomeUnusable       = "unusable"        // response failed schema/correlation checks
	OutcomeNoOutput       = "no_output"       // the process wrote no response or did not run
)

// Querier answers one research query request.
type Querier interface {
	Query(ctx context.Context, request []byte) (*Result, error)
}

// Result is one attempt. RawRequest and RawResponse are the bytes that were
// sent and received; they are saved unmodified under Dir.
type Result struct {
	Provenance      string
	Outcome         string
	Exit            int
	Request         *RequestHead
	Response        *Response // nil when there was no parseable response
	RawRequest      []byte
	RawResponse     []byte
	Stderr          []byte
	bundleDir       string
	ValidationScope string // response or bundle; empty when unusable
	Dir             string // evidence directory of this attempt ("" when not recorded)
}

// Attempt is the attempt.json record written next to the raw evidence.
type Attempt struct {
	Provenance      string    `json:"provenance"`
	Outcome         string    `json:"outcome"`
	Exit            int       `json:"exit"`
	RequestID       string    `json:"request_id,omitempty"`
	AnalysisID      string    `json:"analysis_id,omitempty"`
	Operation       string    `json:"operation,omitempty"`
	ErrorCode       string    `json:"error_code,omitempty"`
	Diagnostic      string    `json:"diagnostic,omitempty"`
	Argv            []string  `json:"argv,omitempty"`
	BinarySHA256    string    `json:"binary_sha256,omitempty"`
	Fixture         string    `json:"fixture,omitempty"`
	RequestHash     string    `json:"request_sha256"`
	ResponseHash    string    `json:"response_sha256,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	Duration        string    `json:"duration"`
	ValidationScope string    `json:"validation_scope,omitempty"`
}

// Recorder allocates one evidence directory per attempt under Root:
// NNNN-<request_id>/{request.json,response.json,stderr.txt,attempt.json}.
type Recorder struct{ Root string }

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (rc Recorder) next(requestID string) (string, error) {
	if err := os.MkdirAll(rc.Root, 0o755); err != nil {
		return "", err
	}
	name := unsafeName.ReplaceAllString(requestID, "_")
	for i := 1; i < 1_000_000; i++ {
		dir := filepath.Join(rc.Root, fmt.Sprintf("%04d-%s", i, name))
		err := os.Mkdir(dir, 0o755)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free evidence directory under %s", rc.Root)
}

func writeAttempt(dir string, a Attempt) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "attempt.json"), append(b, '\n'), 0o644)
}

// finish checks the response, sets the outcome and writes attempt.json.
// It returns the check error, if any.
func finish(res *Result, a *Attempt, started time.Time) error {
	var cerr error
	switch {
	case res.RawResponse == nil:
		res.Outcome = OutcomeNoOutput
	default:
		res.Response, cerr = Check(res.Request, res.Exit, res.RawResponse)

		if cerr == nil {
			res.ValidationScope = "response"
			if res.bundleDir != "" && res.Response.Status == "ok" {
				cerr = checkBundleEvidence(res.bundleDir, res.Request, res.RawResponse)
				if cerr == nil {
					res.ValidationScope = "bundle"
				}
			}
		}
		if cerr != nil {
			res.ValidationScope = ""
		}
		switch {
		case cerr != nil:
			res.Outcome = OutcomeUnusable
		case res.Response.Status == "ok":
			res.Outcome = OutcomeResult
		case res.Exit == 2:
			res.Outcome = OutcomeInvalidRequest
		default:
			res.Outcome = OutcomeFailure
		}
		if res.Response != nil && res.Response.Error != nil {
			a.ErrorCode = res.Response.Error.Code
		}
		a.ResponseHash = sha256Of(res.RawResponse)
	}
	if cerr == nil && res.Provenance == ProvenanceFixture && res.Response != nil &&
		res.Response.Provenance != nil && res.Response.Provenance.Kind != ProvenanceFixture {
		cerr = fmt.Errorf("fixture response has provenance %q", res.Response.Provenance.Kind)
		res.Outcome = OutcomeUnusable
	}
	if cerr == nil && res.Provenance == ProvenanceAnalysis && res.Response != nil &&
		res.Response.Provenance != nil && res.Response.Provenance.Kind != ProvenanceAnalysis {
		cerr = fmt.Errorf("ariadne response has provenance %q", res.Response.Provenance.Kind)
		res.Outcome = OutcomeUnusable
	}
	if cerr != nil {
		res.ValidationScope = ""
	}
	a.ValidationScope = res.ValidationScope
	a.Provenance, a.Outcome, a.Exit = res.Provenance, res.Outcome, res.Exit
	a.RequestID, a.AnalysisID, a.Operation = res.Request.RequestID, res.Request.AnalysisID, res.Request.Operation
	a.RequestHash = sha256Of(res.RawRequest)
	a.StartedAt, a.Duration = started.UTC(), time.Since(started).String()
	if cerr != nil {
		a.Diagnostic = cerr.Error()
	} else if res.Outcome == OutcomeNoOutput && a.Diagnostic == "" {
		a.Diagnostic = "no response document"
	}
	if res.Dir != "" {
		if werr := writeAttempt(res.Dir, *a); werr != nil && cerr == nil {
			cerr = werr
		}
	}
	if cerr == nil && res.Outcome == OutcomeNoOutput {
		cerr = errors.New(a.Diagnostic)
	}
	return cerr
}

// CLI runs the real `ariadne research query` against one bundle.
type CLI struct {
	Binary   string   // path to the ariadne binary
	Bundle   string   // research bundle directory
	Evidence Recorder // where raw requests and responses are kept
	Env      []string // process environment; nil inherits the adapter's

	binarySHA string
}

// Query sends one request. The request bytes are written verbatim to
// request.json and Ariadne writes response.json itself, into a directory
// that did not exist before the call, so the saved response is fresh and
// unmodified. A non-nil error means the response must not be consumed as
// evidence; the Result still holds whatever was produced.
func (c *CLI) Query(ctx context.Context, request []byte) (*Result, error) {
	head, err := ParseRequest(request)
	if err != nil {
		return nil, err
	}
	if c.binarySHA == "" {
		if c.binarySHA, err = fileSHA256(c.Binary); err != nil {
			return nil, fmt.Errorf("ariadne binary: %w", err)
		}
	}
	dir, err := c.Evidence.next(head.RequestID)
	if err != nil {
		return nil, err
	}
	reqPath, respPath := filepath.Join(dir, "request.json"), filepath.Join(dir, "response.json")
	if err := os.WriteFile(reqPath, request, 0o644); err != nil {
		return nil, err
	}
	argv := []string{c.Binary, "research", "query", "-bundle", c.Bundle, "-request", reqPath, "-out", respPath}
	res := &Result{Provenance: ProvenanceAnalysis, Request: head, RawRequest: request, Dir: dir, bundleDir: c.Bundle}
	a := Attempt{Argv: argv, BinarySHA256: c.binarySHA}
	started := time.Now()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr, cmd.Env = &stderr, c.Env
	runErr := cmd.Run()
	res.Stderr = stderr.Bytes()
	_ = os.WriteFile(filepath.Join(dir, "stderr.txt"), res.Stderr, 0o644)
	var ee *exec.ExitError
	switch {
	case runErr == nil:
		res.Exit = 0
	case errors.As(runErr, &ee) && ee.Exited():
		res.Exit = ee.ExitCode()
	default: // did not start, killed, or cancelled
		res.Exit = -1
		a.Diagnostic = runErr.Error()
		if ctx.Err() != nil {
			a.Diagnostic = "interrupted: " + ctx.Err().Error()
		}
		return res, finish(res, &a, started)
	}
	if raw, rerr := os.ReadFile(respPath); rerr == nil {
		res.RawResponse = raw
	} else {
		a.Diagnostic = fmt.Sprintf("exit %d without a response document: %s", res.Exit, firstLine(res.Stderr))
	}
	return res, finish(res, &a, started)
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Bundle is a published research bundle's manifest and identity.
type Bundle struct {
	Dir            string
	AnalysisID     string
	ProvenanceKind string
	RootsMode      string
	Scope          string // "all" or "reachable"; in a reachable bundle unreached non-input methods resolve as missing
	ToolVersion    string
	BinarySHA256   string
	RawManifest    []byte
	RawIdentity    []byte
}

// LoadBundle reads a bundle's manifest.json and identity.json. Ariadne
// verifies the dataset hashes itself on every query.
func LoadBundle(dir string) (*Bundle, error) {
	rawM, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m struct {
		SchemaVersion    string `json:"schema_version"`
		ContractRevision string `json:"contract_revision"`
		AnalysisID       string `json:"analysis_id"`
		IdentityPath     string `json:"identity_path"`
	}
	if err := json.Unmarshal(rawM, &m); err != nil {
		return nil, fmt.Errorf("bundle manifest: %w", err)
	}
	if m.SchemaVersion != BundleSchema || m.ContractRevision != ContractRevision {
		return nil, fmt.Errorf("bundle %s is %s/%s, adapter reads %s/%s", dir, m.SchemaVersion, m.ContractRevision, BundleSchema, ContractRevision)
	}
	if m.IdentityPath == "" || filepath.IsAbs(m.IdentityPath) || m.IdentityPath != filepath.Base(m.IdentityPath) {
		return nil, fmt.Errorf("bundle manifest identity_path %q", m.IdentityPath)
	}
	rawI, err := os.ReadFile(filepath.Join(dir, m.IdentityPath))
	if err != nil {
		return nil, err
	}
	var id struct {
		Provenance struct {
			Kind string `json:"kind"`
		} `json:"provenance"`
		Tool struct {
			Version      string `json:"version"`
			BinarySHA256 string `json:"binary_sha256"`
		} `json:"tool"`
		Configuration struct {
			RootsMode string `json:"roots_mode"`
			Settings  struct {
				Scope string `json:"scope"`
			} `json:"settings"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(rawI, &id); err != nil {
		return nil, fmt.Errorf("bundle identity: %w", err)
	}
	scope := id.Configuration.Settings.Scope
	if scope == "" {
		scope = "all"
	}
	return &Bundle{Dir: dir, AnalysisID: m.AnalysisID, ProvenanceKind: id.Provenance.Kind, RootsMode: id.Configuration.RootsMode, Scope: scope,
		ToolVersion: id.Tool.Version, BinarySHA256: id.Tool.BinarySHA256, RawManifest: rawM, RawIdentity: rawI}, nil
}

// IndexOptions configure `ariadne research index`. Roots is always passed;
// the remaining fields are passed when set.
type IndexOptions struct {
	App      string // -app: the built library or application
	Deps     string // -deps: directory of dependency jars
	DepsList string // -deps-list: `mvn dependency:list` output
	Roots    string // -roots: "all", "profile" or "api" (required)
	Scope    string // -scope: "" (producer default, all), "all" or "reachable"
	Profile  string // -profile
	CacheDir string // -cache-dir: read-only reference data; indexing is offline
	Sources  string // -sources: source directory Ariadne hash-verifies Source.path against
	Out      string // -out: bundle directory; must not exist
	Extra    []string
	Env      []string
}

// IndexResult is one indexing run.
type IndexResult struct {
	Argv   []string
	Exit   int
	Stderr []byte
	Bundle *Bundle // nil unless Exit is 0
}

// Index runs `ariadne research index` and loads the published bundle.
func Index(ctx context.Context, binary string, o IndexOptions) (*IndexResult, error) {
	switch {
	case o.Roots == "":
		return nil, errors.New("research index: Roots is required")
	case o.Out == "":
		return nil, errors.New("research index: Out is required")
	case o.Scope != "" && o.Scope != "all" && o.Scope != "reachable":
		return nil, fmt.Errorf("research index: Scope %q (want all or reachable)", o.Scope)
	}
	argv := []string{binary, "research", "index", "-roots", o.Roots}
	for _, f := range []struct{ flag, v string }{
		{"-app", o.App}, {"-deps", o.Deps}, {"-deps-list", o.DepsList}, {"-scope", o.Scope},
		{"-profile", o.Profile}, {"-cache-dir", o.CacheDir}, {"-sources", o.Sources},
	} {
		if f.v != "" {
			argv = append(argv, f.flag, f.v)
		}
	}
	argv = append(argv, o.Extra...)
	argv = append(argv, "-out", o.Out)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr, cmd.Env = &stderr, o.Env
	err := cmd.Run()
	r := &IndexResult{Argv: argv, Stderr: stderr.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.Exited():
		r.Exit = ee.ExitCode()
		return r, fmt.Errorf("research index: exit %d: %s", r.Exit, lastLine(r.Stderr))
	default:
		r.Exit = -1
		return r, fmt.Errorf("research index: %w", err)
	}
	if r.Bundle, err = LoadBundle(o.Out); err != nil {
		return r, err
	}
	if r.Bundle.ProvenanceKind != ProvenanceAnalysis {
		return r, fmt.Errorf("indexed bundle has provenance %q", r.Bundle.ProvenanceKind)
	}
	if r.Bundle.RootsMode != o.Roots {
		return r, fmt.Errorf("indexed bundle has roots %q, asked for %q", r.Bundle.RootsMode, o.Roots)
	}
	if o.Scope != "" && r.Bundle.Scope != o.Scope {
		return r, fmt.Errorf("indexed bundle has scope %q, asked for %q", r.Bundle.Scope, o.Scope)
	}
	return r, nil
}

// IndexHasFlag reports whether `binary research index -h` lists -name, for
// flags newer than the pinned contract (such as -sources).
func IndexHasFlag(ctx context.Context, binary, name string) bool {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, "research", "index", "-h")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // -h exits non-zero with the flag package
	return regexp.MustCompile(`(?m)^\s*-` + regexp.QuoteMeta(name) + `\b`).Match(out.Bytes())
}

func lastLine(b []byte) string {
	b = bytes.TrimRight(b, "\n")
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	return string(b)
}
