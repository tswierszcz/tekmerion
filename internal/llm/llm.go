// Package llm defines the replaceable bounded model interface used by the controller.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/tswierszcz/tekmerion/internal/state"
)

// MaxTimeoutSeconds bounds one model request, including slow reasoning models
// that keep an HTTP 200 response open with keep-alive whitespace while generating.
const MaxTimeoutSeconds = 600

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Request struct {
	Role             string    `json:"role"`
	Model            string    `json:"model"`
	Provider         string    `json:"provider"`
	PromptRevision   string    `json:"prompt_revision"`
	ExpectedModel    string    `json:"expected_returned_model,omitempty"`
	ExpectedProvider string    `json:"expected_returned_provider,omitempty"`
	Messages         []Message `json:"messages"`
	InputTokenBound  int64     `json:"input_token_bound"`
	MaxOutputTokens  int64     `json:"max_output_tokens"`
	JSONOutput       bool      `json:"json_output"`
}

func (r Request) Validate() error {
	if r.Role != "recon" && r.Role != "hunt" && r.Role != "validate" && r.Role != "report" {
		return fmt.Errorf("unknown model role")
	}
	if r.Model == "" || r.Provider == "" || r.PromptRevision == "" || len(r.Messages) == 0 || r.InputTokenBound <= 0 || r.MaxOutputTokens <= 0 || r.InputTokenBound > math.MaxInt64-r.MaxOutputTokens {
		return fmt.Errorf("model request needs explicit route, prompt revision, messages and finite token bounds")
	}
	for _, m := range r.Messages {
		if (m.Role != "system" && m.Role != "user" && m.Role != "assistant") || m.Content == "" {
			return fmt.Errorf("unsupported or empty message")
		}
	}
	return nil
}

type Result struct {
	RetryAfterMS     int64           `json:"retry_after_ms,omitempty"`
	HTTPStatus       int             `json:"http_status"`
	RawResponse      []byte          `json:"-"`
	Redacted         bool            `json:"credential_redacted"`
	ID               string          `json:"generation_id,omitempty"`
	Model            string          `json:"returned_model,omitempty"`
	Provider         string          `json:"returned_provider,omitempty"`
	Content          string          `json:"content,omitempty"`
	FinishReason     string          `json:"finish_reason,omitempty"`
	RawUsage         json.RawMessage `json:"usage,omitempty"`
	Cost             *state.Money    `json:"normalized_cost_usd"`
	Tokens           *int64          `json:"total_tokens"`
	PromptTokens     *int64          `json:"prompt_tokens"`
	CompletionTokens *int64          `json:"completion_tokens"`
	RouteMismatch    bool            `json:"route_mismatch"`
	Retryable        bool            `json:"retryable"`
	Diagnostic       string          `json:"diagnostic,omitempty"`
}

// Provider does one attempt, with no implicit network retries. The caller owns
// reservations and independent validation of stage-specific structured output.
type Provider interface {
	Complete(context.Context, Request) (*Result, error)
}
