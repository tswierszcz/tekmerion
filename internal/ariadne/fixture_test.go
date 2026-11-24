package ariadne

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const contractDir = "../../contracts/ariadne/v1"

func TestPinMatchesVendoredContract(t *testing.T) {
	p, err := LoadPin("../../contracts/ariadne/PIN.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(contractDir); err != nil {
		t.Fatal(err)
	}
	if p.Status != "upstream-commit" || p.UpstreamCommit == nil || len(*p.UpstreamCommit) != 40 {
		t.Fatalf("pin is not bound to an upstream commit: status %q commit %v", p.Status, p.UpstreamCommit)
	}
}

func TestFixtureReplaysEveryRecordedPair(t *testing.T) {
	ev := Recorder{Root: t.TempDir()}
	f, err := NewFixture(contractDir, ev)
	if err != nil {
		t.Fatal(err)
	}
	reqs := f.Requests()
	if len(reqs) != 9 {
		t.Fatalf("%d recorded pairs: %v", len(reqs), reqs)
	}
	for _, path := range reqs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		res, err := f.Query(context.Background(), raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if res.Provenance != ProvenanceFixture || res.Outcome != OutcomeResult || res.Exit != 0 {
			t.Errorf("%s: provenance %s outcome %s exit %d", path, res.Provenance, res.Outcome, res.Exit)
		}
		if res.Response.Provenance == nil || res.Response.Provenance.Kind != ProvenanceFixture {
			t.Errorf("%s: response provenance %+v", path, res.Response.Provenance)
		}
		// Raw evidence is saved byte for byte.
		savedReq, _ := os.ReadFile(filepath.Join(res.Dir, "request.json"))
		savedResp, _ := os.ReadFile(filepath.Join(res.Dir, "response.json"))
		if !bytes.Equal(savedReq, raw) || !bytes.Equal(savedResp, res.RawResponse) {
			t.Errorf("%s: saved evidence differs from what was exchanged", path)
		}
		attempt, _ := os.ReadFile(filepath.Join(res.Dir, "attempt.json"))
		if !bytes.Contains(attempt, []byte(`"provenance": "fixture"`)) {
			t.Errorf("%s: attempt.json %s", path, attempt)
		}
	}
	// A request nobody recorded is refused, not approximated.
	raw, _ := os.ReadFile(filepath.Join(contractDir, "fixtures/path-found-request.json"))
	other := bytes.Replace(raw, []byte(`"path-found"`), []byte(`"path-found-2"`), 1)
	if _, err := f.Query(context.Background(), other); err == nil || !strings.Contains(err.Error(), "no recorded response") {
		t.Errorf("unknown request: %v", err)
	}
	// Key order and whitespace do not matter.
	compact := []byte(`{"roots":{"selection":"indexed"},"targets":[{"method_id":"m-write","id":"candidate-001"}],"operation":"reachability","request_id":"path-found","analysis_id":"sha256:3c1aba28a034be50d626df77e1ff2f1ee61310029a51c0da7ac3524424601363","schema_version":"ariadne-research-query-1"}`)
	if res, err := f.Query(context.Background(), compact); err != nil || res.Outcome != OutcomeResult {
		t.Errorf("reordered request: %v", err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(contractDir, "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckRejectsUncorrelatedResponses(t *testing.T) {
	reqRaw := readFixture(t, "path-found-request.json")
	req, err := ParseRequest(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	resp := string(readFixture(t, "path-found-response.json"))
	if _, err := Check(req, 0, []byte(resp)); err != nil {
		t.Fatalf("recorded pair: %v", err)
	}
	aid := `"sha256:3c1aba28a034be50d626df77e1ff2f1ee61310029a51c0da7ac3524424601363"`
	cases := []struct {
		name, from, to string
		exit           int
		want           string
	}{
		{"schema", `"ariadne-research-response-1"`, `"ariadne-research-response-2"`, 0, "schema_version"},
		{"revision", `"1.0.0-draft.1"`, `"1.0.0-draft.2"`, 0, "contract_revision"},
		{"request id", `"request_id": "path-found"`, `"request_id": "other"`, 0, "request_id"},
		{"analysis id", `"analysis_id": ` + aid, `"analysis_id": "sha256:` + strings.Repeat("0", 64) + `"`, 0, "analysis_id"},
		{"operation", `"operation": "reachability"`, `"operation": "entries"`, 0, "operation"},
		{"target order", `"target_id": "candidate-001"`, `"target_id": "candidate-002"`, 0, "target"},
		{"exit", "", "", 1, "exit status 1"},
		{"exit outside contract", "", "", 3, "outside the contract"},
	}
	for _, c := range cases {
		body := resp
		if c.from != "" {
			if !strings.Contains(body, c.from) {
				t.Fatalf("%s: %q not in fixture", c.name, c.from)
			}
			body = strings.Replace(body, c.from, c.to, 1)
		}
		if _, err := Check(req, c.exit, []byte(body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error about %s", c.name, err, c.want)
		}
	}
	// The recorded error envelope: exit 2 for INVALID_REQUEST, not 1.
	errResp := readFixture(t, "error-response.json")
	if r, err := Check(req, 2, errResp); err != nil || r.Error.Code != "INVALID_REQUEST" {
		t.Errorf("error envelope with exit 2: %v", err)
	}
	if _, err := Check(req, 1, errResp); err == nil {
		t.Error("INVALID_REQUEST with exit 1 accepted")
	}
}

func TestParseRequestLimitsBatch(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"request_id":"r","targets":[`)
	for i := 0; i <= MaxTargets; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"t"}`)
	}
	b.WriteString("]}")
	if _, err := ParseRequest([]byte(b.String())); err == nil {
		t.Error("257 targets accepted")
	}
	if _, err := ParseRequest([]byte(`{"operation":"entries"}`)); err == nil {
		t.Error("request without request_id accepted")
	}
}

func TestBatches(t *testing.T) {
	ids := make([]int, 600)
	got := Batches(ids)
	if len(got) != 3 || len(got[0]) != 256 || len(got[1]) != 256 || len(got[2]) != 88 {
		t.Fatalf("batch sizes %d", len(got))
	}
	if Batches([]int{}) != nil {
		t.Error("empty input gives batches")
	}
}
