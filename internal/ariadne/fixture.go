package ariadne

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Fixture replays the recorded request/response pairs of the contract
// package (cases.json responses with a "request" that are schema- and
// semantically valid). A request matches when it
// is the same JSON document as a recorded one; anything else is an error.
// Every Result it returns has Provenance "fixture".
type Fixture struct {
	Evidence Recorder
	pairs    map[string]fixturePair
}

type fixturePair struct{ request, response string }

// NewFixture loads the pairs listed in <contractDir>/cases.json.
func NewFixture(contractDir string, evidence Recorder) (*Fixture, error) {
	raw, err := os.ReadFile(filepath.Join(contractDir, "cases.json"))
	if err != nil {
		return nil, err
	}
	var cases struct {
		ContractRevision string `json:"contract_revision"`
		Cases            []struct {
			Path       string `json:"path"`
			Definition string `json:"definition"`
			Request    string `json:"request"`
			Schema     bool   `json:"schema_valid"`
			Semantic   bool   `json:"semantic_valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("cases.json: %w", err)
	}
	if cases.ContractRevision != ContractRevision {
		return nil, fmt.Errorf("cases.json is contract %s, adapter implements %s", cases.ContractRevision, ContractRevision)
	}
	f := &Fixture{Evidence: evidence, pairs: map[string]fixturePair{}}
	for _, c := range cases.Cases {
		// Negative cases reuse a request with a deliberately broken
		// response; only conforming pairs are replayable answers.
		if c.Definition != "Response" || c.Request == "" || !c.Schema || !c.Semantic {
			continue
		}
		reqPath := filepath.Join(contractDir, filepath.FromSlash(c.Request))
		reqRaw, err := os.ReadFile(reqPath)
		if err != nil {
			return nil, err
		}
		key, err := canonical(reqRaw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Request, err)
		}
		if _, dup := f.pairs[key]; dup {
			return nil, fmt.Errorf("%s: two recorded responses for one request", c.Request)
		}
		f.pairs[key] = fixturePair{request: reqPath, response: filepath.Join(contractDir, filepath.FromSlash(c.Path))}
	}
	if len(f.pairs) == 0 {
		return nil, fmt.Errorf("%s has no request/response pairs", contractDir)
	}
	return f, nil
}

// Requests lists the recorded request files, sorted.
func (f *Fixture) Requests() []string {
	var out []string
	for _, p := range f.pairs {
		out = append(out, p.request)
	}
	sort.Strings(out)
	return out
}

// canonical re-encodes a JSON document with sorted object keys.
func canonical(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// Query replays the response recorded for request. The exit status is the
// one the contract assigns to that response.
func (f *Fixture) Query(_ context.Context, request []byte) (*Result, error) {
	head, err := ParseRequest(request)
	if err != nil {
		return nil, err
	}
	key, err := canonical(request)
	if err != nil {
		return nil, err
	}
	pair, ok := f.pairs[key]
	if !ok {
		return nil, fmt.Errorf("fixture adapter: no recorded response for request %q", head.RequestID)
	}
	started := time.Now()
	raw, err := os.ReadFile(pair.response)
	if err != nil {
		return nil, err
	}
	res := &Result{Provenance: ProvenanceFixture, Request: head, RawRequest: request, RawResponse: raw}
	var env Response
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", pair.response, err)
	}
	res.Exit = ExitFor(&env)
	if f.Evidence.Root != "" {
		if res.Dir, err = f.Evidence.next(head.RequestID); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(res.Dir, "request.json"), request, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(res.Dir, "response.json"), raw, 0o644); err != nil {
			return nil, err
		}
	}
	return res, finish(res, &Attempt{Fixture: pair.response}, started)
}

// Batches splits targets into consecutive slices of at most MaxTargets, the
// largest reachability request Ariadne accepts. Each query process loads the
// bundle again, so callers should fill batches rather than send one target
// per request.
func Batches[T any](targets []T) [][]T {
	var out [][]T
	for len(targets) > MaxTargets {
		out = append(out, targets[:MaxTargets:MaxTargets])
		targets = targets[MaxTargets:]
	}
	if len(targets) > 0 {
		out = append(out, targets)
	}
	return out
}
