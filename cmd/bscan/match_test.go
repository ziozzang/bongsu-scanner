package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchCLIReportsAndExitCodes(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "fixture.cdx.json")
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"fixture-ref","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"table", "json", "cyclonedx"} {
		out := filepath.Join(t.TempDir(), "output")
		err := run(context.Background(), []string{"match", "--db", db, "--format", format, "--fail-on", "HIGH", "-o", out, input})
		if exitCode(err) != 2 {
			t.Fatalf("%s: expected findings exit 2, got %v", format, err)
		}
		output, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(output), "CVE-2026-12345") {
			t.Fatalf("%s missing finding: %s", format, output)
		}
		if format != "table" && !json.Valid(output) {
			t.Fatalf("invalid %s JSON", format)
		}
		if format == "cyclonedx" && !strings.Contains(string(output), "fixture-ref") {
			t.Fatal("lost component reference")
		}
	}
	out := filepath.Join(t.TempDir(), "reports.json")
	if err := cmdMatch(context.Background(), []string{"--db", db, "--format", "json", "--ignore", "CVE-2026-12345", "--fail-on", "HIGH", "-o", out, input, input}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var reports []map[string]any
	if err := json.Unmarshal(b, &reports); err != nil || len(reports) != 2 {
		t.Fatalf("multi-input JSON: %v %s", err, b)
	}
	if err := cmdMatch(context.Background(), []string{"--db", db, "--format", "cyclonedx", "-o", input, input}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(input)
	if !json.Valid(b) || !strings.Contains(string(b), "vulnerabilities") {
		t.Fatal("in-place output failed")
	}
}

func TestMatchCLIRejectsInvalidPolicyBeforeOutput(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	for _, args := range [][]string{
		{}, {"--min-severity", "hihg", "input"}, {"--fail-on", "error", "input"},
		{"--format", "xml", "input"}, {"--format", "cyclonedx", "one", "two"},
	} {
		if err := cmdMatch(context.Background(), args); exitCode(err) != 1 {
			t.Fatalf("accepted %v: %v", args, err)
		}
	}
	if exitCode(nil) != 0 {
		t.Fatal("success exit code")
	}
}

func TestScanRejectsInvalidLimitsBeforeSigning(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	for _, flags := range []scanFlags{{format: "invalid", sign: true}, {format: "both", maxFiles: -1, sign: true}, {format: "both", timeout: -1, sign: true}} {
		if _, err := scanOne(context.Background(), t.TempDir(), flags); err == nil {
			t.Fatalf("accepted %+v", flags)
		}
	}
}

func TestReviewLLMFailureKeepsFindingsExitCode(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "0")
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(input, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "report.json")
	err := cmdMatch(context.Background(), []string{"--db", db, "--llm", "--llm-base-url", server.URL + "/v1", "--llm-model", "fixture", "--format", "json", "--fail-on", "HIGH", "-o", out, input})
	var found *findingsError
	if exitCode(err) != 2 || !errors.As(err, &found) || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected joined findings and assessment errors with exit 2: %v", err)
	}
	raw, readErr := os.ReadFile(out)
	if readErr != nil || !json.Valid(raw) || !strings.Contains(string(raw), "CVE-2026-12345") {
		t.Fatalf("finding output lost: %s, %v", raw, readErr)
	}
}
