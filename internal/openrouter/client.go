// Package openrouter implements one bounded, non-streaming HTTP attempt.
package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/state"
)

const Endpoint = "https://openrouter.ai/api/v1/chat/completions"

type Client struct {
	endpoint, key string
	http          *http.Client
	maxBytes      int64
}
type Config struct {
	Endpoint, APIKey string
	Timeout          time.Duration
	MaxResponseBytes int64
}

func FromEnv() (*Client, error) { return New(Config{APIKey: os.Getenv("OPENROUTER_API_KEY")}) }
func New(config Config) (*Client, error) {
	if config.Endpoint == "" {
		config.Endpoint = Endpoint
	}
	u, err := url.Parse(config.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid model endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	local := ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, fmt.Errorf("model endpoint requires HTTPS (HTTP allowed only for loopback tests)")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(config.APIKey) {
		return nil, fmt.Errorf("OPENROUTER_API_KEY is missing or has unsupported characters")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < 0 || config.Timeout > llm.MaxTimeoutSeconds*time.Second {
		return nil, fmt.Errorf("model timeout must be bounded to two minutes")
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 1 << 20
	}
	if config.MaxResponseBytes <= 0 || config.MaxResponseBytes > 4<<20 {
		return nil, fmt.Errorf("response byte cap must be at most 4 MiB")
	}
	return &Client{endpoint: config.Endpoint, key: config.APIKey, maxBytes: config.MaxResponseBytes, http: &http.Client{Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Check is a local preflight; it never sends the credential or request.
func (c *Client) Check(input llm.Request) error {
	if err := input.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if bytes.Contains(raw, []byte(c.key)) {
		return fmt.Errorf("credential appears in model input")
	}
	return nil
}

func (c *Client) Complete(ctx context.Context, input llm.Request) (*llm.Result, error) {
	if err := c.Check(input); err != nil {
		return nil, err
	}
	body := map[string]any{"model": input.Model, "messages": input.Messages, "max_tokens": input.MaxOutputTokens, "stream": false, "provider": map[string]any{"only": []string{input.Provider}, "allow_fallbacks": false, "require_parameters": true}}
	if input.ReasoningMaxTokens > 0 {
		body["reasoning"] = map[string]any{"max_tokens": input.ReasoningMaxTokens}
	} else if input.ReasoningEffort != "" {
		body["reasoning"] = map[string]any{"effort": input.ReasoningEffort}
	}
	if input.JSONOutput {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(payload, []byte(c.key)) {
		return nil, fmt.Errorf("credential appears in model context")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("invalid model HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return &llm.Result{Retryable: ctx.Err() == nil, Diagnostic: "model transport failed; delivery/charge uncertain"}, fmt.Errorf("model transport failed; delivery/charge uncertain")
	}
	defer response.Body.Close()
	result := &llm.Result{HTTPStatus: response.StatusCode}
	if seconds, err := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64); err == nil && seconds > 0 {
		result.RetryAfterMS = min(seconds, int64(30)) * 1000
	} else if date, err := http.ParseTime(response.Header.Get("Retry-After")); err == nil && date.After(time.Now()) {
		result.RetryAfterMS = min(time.Until(date).Milliseconds()+1, int64(30000))
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxBytes+1))
	// No authorization headers, upstream headers or transport URL are retained.
	redacted, changed := c.redact(raw)
	result.Redacted = changed
	result.RawResponse = redacted
	fail := func(message string) (*llm.Result, error) {
		result.Diagnostic = message
		return result, errors.New(message)
	}
	if readErr != nil {
		result.Retryable = ctx.Err() == nil
		return fail("incomplete model response; charge uncertain")
	}
	if int64(len(raw)) > c.maxBytes || int64(len(redacted)) > c.maxBytes {
		result.RawResponse = redacted[:min(int64(len(redacted)), c.maxBytes)]
		return fail("model response exceeds byte cap; charge uncertain")
	}
	var doc struct {
		ID       string          `json:"id"`
		Model    string          `json:"model"`
		Provider string          `json:"provider"`
		Error    json.RawMessage `json:"error"`
		Usage    json.RawMessage `json:"usage"`
		Choices  []struct {
			Message struct {
				Content *string `json:"content"`
				Refusal *string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := jsonx.Decode(result.RawResponse, &doc, true); err != nil {
		result.Retryable = response.StatusCode == 429 || response.StatusCode >= 500
		return fail("malformed model response; charge uncertain")
	}
	result.ID, result.Model, result.Provider, result.RawUsage = doc.ID, doc.Model, doc.Provider, doc.Usage
	if strings.Contains(result.ID, "[REDACTED]") {
		result.ID = ""
	}
	usageErr := normalizeUsage(result)
	hasError := len(doc.Error) > 0 && string(doc.Error) != "null"
	if response.StatusCode < 200 || response.StatusCode >= 300 || hasError {
		result.Retryable = response.StatusCode == 429 || response.StatusCode >= 500
		var e struct {
			Code any `json:"code"`
		}
		if jsonx.Decode(doc.Error, &e, true) == nil {
			switch code := e.Code.(type) {
			case json.Number:
				result.Retryable = result.Retryable || code.String() == "429" || strings.HasPrefix(code.String(), "5")
			case string:
				result.Retryable = result.Retryable || code == "429" || strings.HasPrefix(code, "5")
			}
		}
		return fail("model gateway returned an error")
	}
	if result.Redacted {
		return fail("credential was redacted from provider output; completion unusable")
	}
	if usageErr != nil {
		return fail("invalid model usage accounting")
	}
	if doc.ID == "" || doc.Model == "" {
		return fail("model response lacks generation/model identity")
	}
	expectedModel := input.Model
	if input.ExpectedModel != "" {
		expectedModel = input.ExpectedModel
	}
	expectedProvider := input.Provider
	if input.ExpectedProvider != "" {
		expectedProvider = input.ExpectedProvider
	}
	if doc.Model != expectedModel || doc.Provider == "" || !strings.EqualFold(doc.Provider, expectedProvider) {
		result.RouteMismatch = true
		return fail("returned model/provider differs from the configured route")
	}
	if len(doc.Choices) != 1 || doc.Choices[0].Message.Content == nil || doc.Choices[0].Message.Refusal != nil {
		return fail("model response has no single usable text completion")
	}
	choice := doc.Choices[0]
	result.Content = *choice.Message.Content
	result.FinishReason = choice.FinishReason
	if choice.FinishReason != "stop" {
		return fail("model completion did not finish normally")
	}
	if input.JSONOutput {
		var content map[string]any
		if err := jsonx.Decode([]byte(result.Content), &content, true); err != nil || content == nil {
			return fail("model content is not a valid JSON object")
		}
	}
	return result, nil
}
func normalizeUsage(result *llm.Result) error {
	if len(result.RawUsage) == 0 || string(result.RawUsage) == "null" {
		return nil
	}
	var usage struct {
		Prompt     *int64          `json:"prompt_tokens"`
		Completion *int64          `json:"completion_tokens"`
		Total      *int64          `json:"total_tokens"`
		Cost       json.RawMessage `json:"cost"`
	}
	if err := jsonx.Decode(result.RawUsage, &usage, true); err != nil {
		return err
	}
	for _, n := range []*int64{usage.Prompt, usage.Completion, usage.Total} {
		if n != nil && *n < 0 {
			return fmt.Errorf("negative token usage")
		}
	}
	result.PromptTokens, result.CompletionTokens = usage.Prompt, usage.Completion
	if usage.Prompt != nil && usage.Completion != nil {
		if *usage.Prompt > math.MaxInt64-*usage.Completion {
			return fmt.Errorf("usage overflow")
		}
		total := *usage.Prompt + *usage.Completion
		if usage.Total != nil && *usage.Total != total {
			return fmt.Errorf("contradictory token totals")
		}
		result.Tokens = &total
	} else {
		result.Tokens = usage.Total
	}
	if len(usage.Cost) > 0 && string(usage.Cost) != "null" {
		var number json.Number
		if err := jsonx.Decode(usage.Cost, &number, true); err != nil {
			return err
		}
		cost, err := charge(number.String())
		if err != nil {
			return err
		}
		result.Cost = &cost
	}
	return nil
}
func charge(decimal string) (state.Money, error) {
	if len(decimal) > 128 {
		return 0, fmt.Errorf("cost too long")
	}
	// Reject overflow/underflow exponents before constructing a big rational.
	n := json.Number(decimal)
	f, err := n.Float64()
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid cost")
	}
	if f == 0 && strings.ContainsAny(decimal, "eE") {
		for _, c := range strings.FieldsFunc(decimal, func(r rune) bool { return r == 'e' || r == 'E' })[0] {
			if c >= '1' && c <= '9' {
				return 0, fmt.Errorf("cost exponent underflow")
			}
		}
	}
	r, ok := new(big.Rat).SetString(decimal)
	if !ok || r.Sign() < 0 {
		return 0, fmt.Errorf("invalid cost")
	}
	r.Mul(r, new(big.Rat).SetInt64(int64(state.Dollar)))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(r.Num(), r.Denom(), rem)
	if rem.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, fmt.Errorf("cost overflow")
	}
	return state.Money(q.Int64()), nil
}

// redact also handles JSON-escaped credential text. Preserve original bytes
// when no credential was present; explicitly mark any rewritten evidence.
func (c *Client) redact(raw []byte) ([]byte, bool) {
	literal := bytes.ReplaceAll(raw, []byte(c.key), []byte("[REDACTED]"))
	changed := !bytes.Equal(literal, raw)
	var value any
	if jsonx.Decode(literal, &value, true) != nil {
		return literal, changed
	}
	decodedChange := false
	var scrub func(any) any
	scrub = func(v any) any {
		switch typed := v.(type) {
		case string:
			clean := strings.ReplaceAll(typed, c.key, "[REDACTED]")
			if clean != typed {
				decodedChange = true
			}
			return clean
		case []any:
			for i, item := range typed {
				typed[i] = scrub(item)
			}
			return typed
		case map[string]any:
			clean := map[string]any{}
			for key, item := range typed {
				safeKey := strings.ReplaceAll(key, c.key, "[REDACTED]")
				if safeKey != key {
					decodedChange = true
				}
				clean[safeKey] = scrub(item)
			}
			return clean
		default:
			return v
		}
	}
	safe := scrub(value)
	if decodedChange {
		encoded, err := json.Marshal(safe)
		if err == nil {
			return encoded, true
		}
	}
	return literal, changed
}
