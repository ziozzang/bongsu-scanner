package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
)

func TestLLMCLIContextCacheAndFailOn(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	t.Setenv("BSCAN_LLM_API_KEY", "test-key")
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"private-root","properties":[{"name":"bscan:host:hostname","value":"private-host"},{"name":"bscan:host:ip-addresses","value":"192.0.2.123"}]}},"components":[{"type":"library","bom-ref":"fixture-ref","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0","properties":[{"name":"bscan:source","value":"/private/project/package-lock.json"}]}]}`
	if err := os.WriteFile(input, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Method != "POST" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing authorization")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		for _, secret := range []string{"private-root", "private-host", "192.0.2.123", "/private/project"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("unnecessary context transmitted: %s", secret)
			}
		}
		if !strings.Contains(string(body), "linux") || !strings.Contains(string(body), "Windows") {
			t.Errorf("missing OS/advisory context: %s", body)
		}
		answer := `{"status":"likely_not_affected","reason":"The advisory restricts the issue to Windows; the declared target is Linux.","evidence":["This vulnerability occurs only on Windows."],"preconditions":["The target OS is Linux."],"checks":["Confirm the affected component is not invoked through a Windows compatibility layer."]}`
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": answer}, "finish_reason": "stop"}}})
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "report.json")
	args := []string{"--db", db, "--llm", "--llm-base-url", server.URL + "/v1", "--llm-model", "fixture-model", "--target-os", "linux", "--target-arch", "amd64", "--format", "json", "--fail-on", "HIGH", "-o", out, input}
	for i := 0; i < 2; i++ {
		err := cmdMatch(context.Background(), args)
		if exitCode(err) != 2 {
			t.Fatalf("LLM must preserve fail-on: %v", err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var report matcher.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if len(report.Findings) != 1 || report.Findings[0].Assessment == nil {
			t.Fatalf("finding/assessment missing: %s", raw)
		}
		if report.Findings[0].Assessment.Status != "likely_not_affected" {
			t.Fatalf("unexpected assessment: %+v", report.Findings[0].Assessment)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cache failed; calls=%d", calls.Load())
	}
}

func TestLLMCLIErrorPreservesReportAndOfflineBlocks(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"r","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "backend error", 503) }))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "report.json")
	args := []string{"--db", db, "--llm", "--llm-base-url", server.URL + "/v1", "--llm-model", "fixture-model", "--format", "json", "-o", out, input}
	err := cmdMatch(context.Background(), args)
	if err == nil || exitCode(err) != 1 {
		t.Fatalf("expected analysis error: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report matcher.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatal("LLM failure erased finding")
	}
	before := calls.Load()
	t.Setenv("BONGSU_OFFLINE", "1")
	if err := cmdMatch(context.Background(), args); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("offline made model request")
	}
	if err := cmdMatch(context.Background(), []string{"--db", db, "--format", "json", "-o", out, input}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("default matching made model request")
	}
}
