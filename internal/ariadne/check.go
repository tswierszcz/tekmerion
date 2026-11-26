package ariadne

import (
	"encoding/json"
	"fmt"
)

// RequestHead is what the adapter reads from a request to check its answer.
// The raw request is what is sent and saved; this is never re-encoded.
type RequestHead struct {
	SchemaVersion string           `json:"schema_version"`
	AnalysisID    string           `json:"analysis_id"`
	RequestID     string           `json:"request_id"`
	Operation     string           `json:"operation"`
	Limits        map[string]int64 `json:"limits"`
	Roots         struct {
		Selection string   `json:"selection"`
		NodeIDs   []string `json:"node_ids"`
	} `json:"roots"`
	Targets []struct {
		ID       string            `json:"id"`
		MethodID string            `json:"method_id"`
		Selector map[string]string `json:"selector"`
	} `json:"targets"`
}

// TargetIDs lists the request's target ids in order.
func (h *RequestHead) TargetIDs() []string {
	ids := make([]string, len(h.Targets))
	for i, t := range h.Targets {
		ids[i] = t.ID
	}
	return ids
}

// ParseRequest reads the fields the adapter correlates on. It rejects a
// request the adapter cannot correlate (no request_id, a batch over
// MaxTargets); the producer stays the judge of everything else.
func ParseRequest(raw []byte) (*RequestHead, error) {
	var h RequestHead
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("request is not a JSON object: %w", err)
	}
	if h.RequestID == "" {
		return nil, fmt.Errorf("request has no request_id")
	}
	if len(h.Targets) > MaxTargets {
		return nil, fmt.Errorf("request %s has %d targets; a batch holds at most %d", h.RequestID, len(h.Targets), MaxTargets)
	}
	return &h, nil
}

// Response is the part of a response envelope the adapter checks. The
// complete document stays available as Result.RawResponse.
type Response struct {
	SchemaVersion    string  `json:"schema_version"`
	ContractRevision string  `json:"contract_revision"`
	Status           string  `json:"status"`
	AnalysisID       *string `json:"analysis_id"`
	RequestID        *string `json:"request_id"`
	Operation        *string `json:"operation"`
	Provenance       *struct {
		Kind     string `json:"kind"`
		Producer string `json:"producer"`
		Revision string `json:"revision"`
	} `json:"provenance"`
	Results []TargetResult `json:"results"`
	Error   *ErrorBody     `json:"error"`
}

// TargetResult is one reachability result; the three assessment axes stay
// separate.
type TargetResult struct {
	TargetID        string `json:"target_id"`
	Resolution      string `json:"resolution"`
	TotalEntryCount *int   `json:"total_entry_count"`
	Search          struct {
		State        string `json:"state"`
		WorkComplete bool   `json:"work_complete"`
	} `json:"search"`
	Model struct {
		State          string   `json:"state"`
		RelevantGapIDs []string `json:"relevant_gap_ids"`
	} `json:"model"`
	Entries []struct {
		RootNodeID     string   `json:"root_node_id"`
		Character      []string `json:"character"`
		ClientDispatch bool     `json:"client_dispatch"`
		Path           struct {
			NodeIDs []string `json:"node_ids"`
			EdgeIDs []string `json:"edge_ids"`
		} `json:"path"`
	} `json:"entries"`
}

// ErrorBody is the producer's error.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// requestErrorCodes are the codes Ariadne answers with exit status 2.
var requestErrorCodes = map[string]bool{
	"INVALID_REQUEST": true, "UNSUPPORTED_SCHEMA": true, "UNSUPPORTED_OPERATION": true,
	"UNSUPPORTED_FILTER": true, "ANALYSIS_MISMATCH": true, "INVALID_CURSOR": true, "ROOTS_OUTSIDE_INDEX": true,
}

// ExitFor is the exit status the contract assigns to a response: 0 for a
// result, 2 for an invalid request, 1 for a bundle, I/O or internal failure.
func ExitFor(r *Response) int {
	if r.Status == "ok" {
		return 0
	}
	if r.Error != nil && requestErrorCodes[r.Error.Code] {
		return 2
	}
	return 1
}

// Check parses a response and correlates it with its request and the exit
// status that came with it. A nil error means the response can be consumed
// as evidence (an error response included: it is a valid answer).
func Check(req *RequestHead, exit int, raw []byte) (*Response, error) {
	if exit != 0 && exit != 1 && exit != 2 {
		return nil, fmt.Errorf("exit status %d is outside the contract (0, 1, 2)", exit)
	}
	doc, err := validateResponseSchema(raw)
	if err != nil {
		return nil, fmt.Errorf("response schema: %w", err)
	}
	var r Response
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("response is not JSON: %w", err)
	}
	if r.SchemaVersion != ResponseSchema {
		return &r, fmt.Errorf("response schema_version %q, want %q", r.SchemaVersion, ResponseSchema)
	}
	if r.ContractRevision != ContractRevision {
		return &r, fmt.Errorf("response contract_revision %q, want %q", r.ContractRevision, ContractRevision)
	}
	switch r.Status {
	case "ok":
		if r.Error != nil {
			return &r, fmt.Errorf("ok response carries an error")
		}
	case "error":
		if r.Error == nil {
			return &r, fmt.Errorf("error response has no error body")
		}
	default:
		return &r, fmt.Errorf("response status %q", r.Status)
	}
	if want := ExitFor(&r); exit != want {
		code := ""
		if r.Error != nil {
			code = " " + r.Error.Code
		}
		return &r, fmt.Errorf("exit status %d with a %s%s response, contract says %d", exit, r.Status, code, want)
	}
	// Correlation. An error envelope may leave an id null when the request
	// could not be read; an ok response must echo all of them.
	if r.Status == "ok" || r.RequestID != nil {
		if r.RequestID == nil || *r.RequestID != req.RequestID {
			return &r, fmt.Errorf("response request_id %s, request %q", strOrNull(r.RequestID), req.RequestID)
		}
	}
	if r.Status == "ok" || r.AnalysisID != nil {
		if r.AnalysisID == nil || *r.AnalysisID != req.AnalysisID {
			return &r, fmt.Errorf("response analysis_id %s, request %q", strOrNull(r.AnalysisID), req.AnalysisID)
		}
	}
	if r.Status == "ok" || r.Operation != nil {
		if r.Operation == nil || *r.Operation != req.Operation {
			return &r, fmt.Errorf("response operation %s, request %q", strOrNull(r.Operation), req.Operation)
		}
	}
	if r.Status == "ok" && req.Operation == "reachability" {
		ids := req.TargetIDs()
		if len(r.Results) != len(ids) {
			return &r, fmt.Errorf("%d results for %d targets", len(r.Results), len(ids))
		}
		for i, res := range r.Results {
			if res.TargetID != ids[i] {
				return &r, fmt.Errorf("result %d is target %q, request has %q there", i, res.TargetID, ids[i])
			}
		}
	}
	if err := checkEvidence(req, doc); err != nil {
		return &r, err
	}
	return &r, nil
}

func strOrNull(s *string) string {
	if s == nil {
		return "null"
	}
	return fmt.Sprintf("%q", *s)
}
