package assessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testInput() Input {
	return Input{AdvisoryID: "CVE-2025-1234", Summary: "Platform-specific vulnerability", Description: "This vulnerability affects Windows only. A local service must be enabled.", Package: "example", Version: "1.0", Ecosystem: "npm", Environment: Environment{OS: "linux", Arch: "amd64", Facts: map[string]string{"service": "disabled"}}}
}

const validResult = `{"status":"likely_not_affected","reason":"The stated Windows-only precondition appears inconsistent with the supplied Linux environment; review is still needed.","evidence":["This vulnerability affects Windows only."],"preconditions":["Windows environment"],"checks":["Confirm the deployed runtime is Linux."]}`

func completion(w http.ResponseWriter, content string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
}
func localClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL + "/v1", Model: "local-model", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestTLSRequestAndEvidenceGroundedCache(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-private-key" {
			t.Errorf("unexpected request method/path/auth")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if string(body["model"]) != `"chosen-model"` || string(body["response_format"]) != `{"type":"json_object"}` || body["tools"] != nil {
			t.Errorf("request contract = %v", body)
		}
		var messages []map[string]string
		_ = json.Unmarshal(body["messages"], &messages)
		if len(messages) != 2 || !strings.Contains(messages[0]["content"], "untrusted DATA") || messages[1]["role"] != "user" {
			t.Error("missing instruction/data separation")
		}
		completion(w, validResult)
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "cache")
	c, err := New(Config{BaseURL: srv.URL + "/v1/", Model: "chosen-model", APIKey: "test-private-key", CacheDir: cache})
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = srv.Client().Transport
	first, err := c.Analyze(context.Background(), testInput())
	if err != nil || first.Status != LikelyNotAffected || first.Cached || first.Model != "chosen-model" || len(first.InputSHA256) != 64 {
		t.Fatalf("result=%+v err=%v", first, err)
	}
	second, err := c.Analyze(context.Background(), testInput())
	if err != nil || !second.Cached || second.InputSHA256 != first.InputSHA256 || calls.Load() != 1 {
		t.Fatalf("cached=%+v calls=%d err=%v", second, calls.Load(), err)
	}
	info, err := os.Stat(filepath.Join(cache, first.InputSHA256+".json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("cache permissions: %v %v", info, err)
	}
	raw, err := os.ReadFile(filepath.Join(cache, first.InputSHA256+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "test-private-key") {
		t.Fatal("credential cached")
	}
	input := testInput()
	input.Environment.Facts["service"] = "enabled"
	changed, err := c.Analyze(context.Background(), input)
	if err != nil || changed.Cached || changed.InputSHA256 == first.InputSHA256 || calls.Load() != 2 {
		t.Fatalf("changed facts reused cache: %+v %v", changed, err)
	}
}

func TestUnsupportedConclusionsBecomeNeedsReview(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		change        func(*Input)
	}{
		{"invented-evidence", strings.Replace(validResult, "This vulnerability affects Windows only.", "All Linux installations are safe.", 1), nil},
		{"missing-os", validResult, func(in *Input) { in.Environment.OS = "" }},
		{"truncated", validResult, func(in *Input) { in.DescriptionTruncated = true }},
		{"no-evidence", strings.Replace(validResult, `["This vulnerability affects Windows only."]`, `[]`, 1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { completion(w, tc.content) })
			in := testInput()
			if tc.change != nil {
				tc.change(&in)
			}
			got, err := c.Analyze(context.Background(), in)
			if err != nil || got.Status != NeedsReview {
				t.Fatalf("result=%+v err=%v", got, err)
			}
		})
	}
}

func TestRejectsInvalidModelOutput(t *testing.T) {
	for _, content := range []string{
		`{"status":"safe","reason":"ok","evidence":[],"preconditions":[],"checks":[]}`,
		`{"status":"needs_review","status":"likely_not_affected","reason":"ok","evidence":[],"preconditions":[],"checks":[]}`,
		`{"status":"needs_review","reason":"ok","evidence":null,"preconditions":[],"checks":[]}`,
		`{"status":"needs_review","reason":"ok","evidence":[],"preconditions":[],"checks":[],"execute":"rm -rf"}`,
		validResult + ` {}`,
		strings.Replace(validResult, `"reason":"`, `"reason":"\u001b[31m`, 1),
		strings.Replace(validResult, `"reason":"`, `"reason":"`+strings.Repeat("x", 1201), 1),
	} {
		c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { completion(w, content) })
		if _, err := c.Analyze(context.Background(), testInput()); err == nil {
			t.Fatalf("invalid output accepted: %.80s", content)
		}
	}
}

func TestEndpointPolicy(t *testing.T) {
	for _, base := range []string{"http://example.com/v1", "http://localhost.evil/v1", "http://127.0.0.1.evil/v1", "https://user:secret@example.com/v1", "https://example.com/v1?api_key=secret", "https://example.com/v1#secret", "file:///tmp/model", ""} {
		if _, err := New(Config{BaseURL: base, Model: "model"}); err == nil {
			t.Errorf("endpoint accepted: %s", base)
		}
	}
	for _, base := range []string{"http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://[::1]:11434/v1", "https://example.com/v1"} {
		if _, err := New(Config{BaseURL: base, Model: "model"}); err != nil {
			t.Errorf("endpoint rejected: %s %v", base, err)
		}
	}
	if _, err := New(Config{BaseURL: "https://example.com/v1"}); err == nil {
		t.Fatal("missing model accepted")
	}
}

func TestRedirectNeverForwardsCredentials(t *testing.T) {
	var reached atomic.Bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer sink.Close()
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	})
	c.config.APIKey = "secret-no-leak"
	_, err := c.Analyze(context.Background(), testInput())
	if err == nil || !strings.Contains(err.Error(), "307") || reached.Load() {
		t.Fatalf("redirect followed=%t err=%v", reached.Load(), err)
	}
}

func TestErrorsAreBoundedAndDoNotExposeProviderContent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"http-error", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			fmt.Fprint(w, "private-key secret provider content")
		}},
		{"oversized", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", maxResponseBytes+1)) }},
		{"truncated-completion", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"choices":[{"finish_reason":"length","message":{"content":"private-key"}}]}`)
		}},
		{"invalid-envelope", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "private-key") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := localClient(t, tc.handler)
			c.config.APIKey = "private-key"
			_, err := c.Analyze(context.Background(), testInput())
			if err == nil || strings.Contains(err.Error(), "private-key") || strings.Contains(err.Error(), "secret provider") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	})
	c.config.Timeout = 20 * time.Millisecond
	if _, err := c.Analyze(context.Background(), testInput()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Analyze(ctx, testInput()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestCorruptCacheRevalidated(t *testing.T) {
	var calls atomic.Int32
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); completion(w, validResult) })
	c.config.CacheDir = t.TempDir()
	first, err := c.Analyze(context.Background(), testInput())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.config.CacheDir, first.InputSHA256+".json")
	first.Evidence = []string{"invented evidence"}
	raw, _ := json.Marshal(first)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := c.Analyze(context.Background(), testInput())
	if err != nil || got.Status != NeedsReview || !got.Cached || calls.Load() != 1 {
		t.Fatalf("cache evidence unchecked: %+v %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"status":"safe"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = c.Analyze(context.Background(), testInput())
	if err != nil || got.Cached || calls.Load() != 2 {
		t.Fatalf("invalid cache not ignored: %+v %v", got, err)
	}
}

func TestInputBoundPreventsRequest(t *testing.T) {
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid input sent")
		io.WriteString(w, "unexpected")
	})
	in := testInput()
	in.Description = strings.Repeat("x", MaxDescriptionBytes+1)
	if _, err := c.Analyze(context.Background(), in); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestCacheKeyIncludesModelEndpointAndAllAdvisoryFields(t *testing.T) {
	var calls atomic.Int32
	c, srv := localClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); completion(w, validResult) })
	c.config.CacheDir = t.TempDir()
	original, err := c.Analyze(context.Background(), testInput())
	if err != nil {
		t.Fatal(err)
	}
	originalConfig := c.config
	variants := []func(*Client, *Input){
		func(c *Client, in *Input) { c.config.Model = "another-model" },
		func(c *Client, in *Input) { c.config.BaseURL = srv.URL + "/another/v1" },
		func(c *Client, in *Input) { in.References = []string{"https://example.com/advisory"} },
		func(c *Client, in *Input) { in.DescriptionTruncated = true },
		func(c *Client, in *Input) { in.Environment.OSVersion = "new-version" },
	}
	seen := map[string]bool{original.InputSHA256: true}
	for _, change := range variants {
		c.config = originalConfig
		in := testInput()
		change(c, &in)
		got, err := c.Analyze(context.Background(), in)
		if err != nil || got.Cached || seen[got.InputSHA256] {
			t.Fatalf("cache key collision %+v %v", got, err)
		}
		seen[got.InputSHA256] = true
	}
	if calls.Load() != int32(len(variants)+1) {
		t.Fatalf("requests=%d", calls.Load())
	}
}

func TestProviderCannotEchoCredentialIntoAssessment(t *testing.T) {
	content := strings.Replace(validResult, `"checks":[`, `"checks":["my-secret-key",`, 1)
	c, _ := localClient(t, func(w http.ResponseWriter, r *http.Request) { completion(w, content) })
	c.config.APIKey = "my-secret-key"
	_, err := c.Analyze(context.Background(), testInput())
	if err == nil || strings.Contains(err.Error(), "my-secret-key") {
		t.Fatalf("credential leak: %v", err)
	}
}
