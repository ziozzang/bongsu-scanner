package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// match --format html|markdown|csv|sarif renders the report package output
// directly, with the SBOM's scan/OS context, and -o accepts device paths.
func TestMatchReportFormats(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	db := cliTestDB(t)
	input := filepath.Join(t.TempDir(), "input.json")
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"fixture-host","properties":[{"name":"bscan:scan:partial","value":"true"}]}},"components":[{"type":"library","bom-ref":"fixture-ref","name":"fixture","version":"1.0.0","purl":"pkg:npm/fixture@1.0.0"}]}`
	if err := os.WriteFile(input, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"html", "markdown", "md", "csv", "sarif"} {
		out := filepath.Join(t.TempDir(), "out."+format)
		if err := cmdMatch(context.Background(), []string{"--db", db, "--format", format, "-o", out, input}); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		switch format {
		case "html":
			if !strings.Contains(body, "<html") || !strings.Contains(body, "fixture") || !strings.Contains(body, "fixture-host") {
				t.Fatalf("html report incomplete: %.200s", body)
			}
		case "markdown", "md":
			if !strings.Contains(body, "|") || !strings.Contains(body, "fixture") {
				t.Fatalf("markdown report incomplete: %.200s", body)
			}
		case "csv":
			rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
			if err != nil || len(rows) < 2 {
				t.Fatalf("csv report invalid: %v rows=%d", err, len(rows))
			}
		case "sarif":
			var doc struct {
				Version string           `json:"version"`
				Runs    []map[string]any `json:"runs"`
			}
			if err := json.Unmarshal(data, &doc); err != nil || doc.Version != "2.1.0" || len(doc.Runs) != 1 {
				t.Fatalf("sarif report invalid: %v %+v", err, doc)
			}
		}
	}
	if err := cmdMatch(context.Background(), []string{"--db", db, "--format", "html", "-o", "/dev/null", input}); err != nil {
		t.Fatalf("device output path must be accepted: %v", err)
	}
	second := filepath.Join(t.TempDir(), "second.json")
	if err := os.WriteFile(second, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdMatch(context.Background(), []string{"--db", db, "--format", "html", input, second}); err == nil {
		t.Fatal("html output with two inputs must be rejected")
	}
}
