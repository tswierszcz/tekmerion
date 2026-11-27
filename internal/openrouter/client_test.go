package openrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tswierszcz/tekmerion/internal/llm"
)

func request() llm.Request {
	return llm.Request{Role: "recon", Model: "test/model", Provider: "provider", PromptRevision: "recon-1", Messages: []llm.Message{{Role: "user", Content: "Return a JSON object"}}, InputTokenBound: 100, MaxOutputTokens: 20, JSONOutput: true}
}

const success = `{"id":"gen-1","model":"test/model","provider":"provider","choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,"cost":0,"prompt_tokens_details":{"cached_tokens":4},"completion_tokens_details":{"reasoning_tokens":1},"cost_details":{"upstream_inference_cost":0.5}}}`

func TestRequestAndUsageAccounting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("wrong endpoint/auth")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(raw), "test-secret") {
			t.Error("credential in request body")
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		route := body["provider"].(map[string]any)
		if route["allow_fallbacks"] != false || route["require_parameters"] != true || len(route["only"].([]any)) != 1 || body["max_tokens"] != float64(20) || body["stream"] != false {
			t.Error("unbounded/unsupported request")
		}
		w.Write([]byte(success))
	}))
	defer server.Close()
	client, err := New(Config{Endpoint: server.URL, APIKey: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Complete(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if result.Cost == nil || *result.Cost != 0 || result.Tokens == nil || *result.Tokens != 12 || !strings.Contains(string(result.RawUsage), "reasoning_tokens") {
		t.Fatalf("usage double-counted or zero lost: %+v", result)
	}
}
func TestErrorsMissingCostAndMalformedOutput(t *testing.T) {
	cases := []struct {
		name, body              string
		status                  int
		wantErr, retry, missing bool
	}{
		{"missing cost", strings.Replace(success, `"cost":0,`, "", 1), 200, false, false, true},
		{"HTTP 200 error", `{"error":{"code":503,"message":"unavailable"},"usage":{"cost":0}}`, 200, true, true, false},
		{"rate limit", `{"error":{"code":429}}`, 429, true, true, true},
		{"malformed", `{`, 200, true, false, true},
		{"duplicate cost", strings.Replace(success, `"cost":0`, `"cost":1,"cost":0`, 1), 200, true, false, true},
		{"invalid JSON content", strings.Replace(success, `{\"ok\":true}`, `not JSON`, 1), 200, true, false, false},
		{"unknown route", strings.Replace(success, `"provider":"provider"`, `"provider":"another"`, 1), 200, true, false, false},
		{"truncated", strings.Replace(success, `"finish_reason":"stop"`, `"finish_reason":"length"`, 1), 200, true, false, false},
		{"contradictory usage", strings.Replace(success, `"total_tokens":12`, `"total_tokens":999`, 1), 200, true, false, true},
		{"fractional scientific cost", strings.Replace(success, `"cost":0`, `"cost":1e-10`, 1), 200, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			client, err := New(Config{Endpoint: server.URL, APIKey: "secret-key"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Complete(context.Background(), request())
			if (err != nil) != tc.wantErr || result == nil {
				t.Fatalf("unexpected response: %+v %v", result, err)
			}
			if result.Retryable != tc.retry || (result.Cost == nil) != tc.missing {
				t.Fatalf("lost retry/cost state: %+v", result)
			}
			if tc.name == "fractional scientific cost" && *result.Cost != 1 {
				t.Fatal("charge rounded down")
			}
		})
	}
}
func TestCredentialRedactionRedirectTimeoutAndSize(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, _ := New(Config{Endpoint: server.URL, APIKey: "very-secret"})
	if _, err := client.Complete(context.Background(), request()); err == nil || redirected.Load() != 0 {
		t.Fatal("credential-bearing redirect followed")
	}
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"error":{"message":"very-secret"}}`)) }))
	defer echo.Close()
	client, _ = New(Config{Endpoint: echo.URL, APIKey: "very-secret"})
	result, err := client.Complete(context.Background(), request())
	if err == nil || !result.Redacted || strings.Contains(string(result.RawResponse), "very-secret") || strings.Contains(err.Error(), "very-secret") {
		t.Fatal("credential persisted")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer slow.Close()
	client, _ = New(Config{Endpoint: slow.URL, APIKey: "very-secret", Timeout: 20 * time.Millisecond})
	result, err = client.Complete(context.Background(), request())
	if err == nil || !result.Retryable {
		t.Fatal("timeout not classified uncertain")
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 100))) }))
	defer large.Close()
	client, _ = New(Config{Endpoint: large.URL, APIKey: "very-secret", MaxResponseBytes: 10})
	result, err = client.Complete(context.Background(), request())
	if err == nil || len(result.RawResponse) > 10 {
		t.Fatal("response cap not enforced")
	}
	bad := request()
	bad.Messages[0].Content = "very-secret"
	if _, err := client.Complete(context.Background(), bad); err == nil {
		t.Fatal("credential in model context accepted")
	}
	if _, err := New(Config{Endpoint: "http://example.com", APIKey: "very-secret"}); err == nil {
		t.Fatal("remote plaintext credential endpoint accepted")
	}
}

func TestJSONEscapedCredentialRedaction(t *testing.T) {
	client, err := New(Config{APIKey: "secret-key"})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"error":{"message":"\u0073ecret-key"},"nested":["\u0073ecret-key"]}`)
	clean, changed := client.redact(raw)
	if !changed {
		t.Fatal("escaped credential not detected")
	}
	var decoded map[string]any
	if err := json.Unmarshal(clean, &decoded); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clean), "secret-key") || strings.Contains(string(clean), `\u0073ecret-key`) {
		t.Fatal("escaped credential retained")
	}
}
func TestClientTimeoutBound(t *testing.T) {
	if _, err := New(Config{APIKey: "k", Timeout: llm.MaxTimeoutSeconds * time.Second}); err != nil {
		t.Fatalf("rejected the maximum request timeout: %v", err)
	}
	if _, err := New(Config{APIKey: "k", Timeout: (llm.MaxTimeoutSeconds + 1) * time.Second}); err == nil {
		t.Fatal("accepted a timeout above the cap")
	}
}
