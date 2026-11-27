package llm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckReasoning(t *testing.T) {
	for _, tc := range []struct {
		max, tokens int64
		effort      string
		ok          bool
	}{
		{100, 0, "", true},
		{100, 99, "", true},
		{100, 100, "", false}, // no room left for the answer
		{100, -1, "", false},
		{100, 0, "high", true},
		{100, 0, "extreme", false},
		{100, 50, "low", false}, // one form only
	} {
		if err := CheckReasoning(tc.max, tc.tokens, tc.effort); (err == nil) != tc.ok {
			t.Errorf("CheckReasoning(%d, %d, %q) = %v, want ok=%v", tc.max, tc.tokens, tc.effort, err, tc.ok)
		}
	}
}

// Unset reasoning limits must not change the recorded request, so earlier
// request identities stay stable.
func TestUnsetReasoningOmitted(t *testing.T) {
	r := Request{Role: "hunt", Model: "m", Provider: "p", PromptRevision: "x", Messages: []Message{{Role: "user", Content: "c"}}, InputTokenBound: 1, MaxOutputTokens: 2}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "reasoning") {
		t.Fatalf("unset reasoning recorded: %s", raw)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.ReasoningMaxTokens = 2
	if r.Validate() == nil {
		t.Fatal("reasoning limit equal to max_output_tokens accepted")
	}
}
