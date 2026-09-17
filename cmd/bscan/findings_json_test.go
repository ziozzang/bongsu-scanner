package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/match"
)

func checkFindingsDocument(t *testing.T, data []byte) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "generated_at", "tool", "findings", "subjects", "matched", "skipped", "by_severity", "db", "severity_policy"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
	for _, key := range []string{"Findings", "Subjects", "Matched", "Skipped", "BySeverity", "DB", "SeverityPolicy"} {
		if _, ok := raw[key]; ok {
			t.Errorf("legacy key %s", key)
		}
	}
	var r match.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != match.FindingsSchema || r.Tool == nil || r.Tool.Name != "bscan" || r.Tool.Version != version || r.GeneratedAt.Location() != time.UTC || r.GeneratedAt.IsZero() || r.Findings == nil {
		t.Fatalf("metadata: %+v", r)
	}
	for _, f := range r.Findings {
		if f.Subject.PURL.String() != "pkg:npm/fixture@1.0.0" {
			t.Fatalf("PURL roundtrip: %+v", f.Subject)
		}
	}
}

func TestFindingsSchemaCLIPaths(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	db, target := cliTestDB(t), scanMatchFixture(t)
	for _, command := range []string{"scan", "batch"} {
		t.Run(command, func(t *testing.T) {
			out := t.TempDir()
			if err := run(context.Background(), []string{command, "--no-sign", "--match", "--db", db, "--output", out, target}); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(out, "*.findings.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("outputs: %v, %v", files, err)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			checkFindingsDocument(t, data)
			if err := run(context.Background(), []string{"report", "--from", files[0], "--format", "sarif", "-o", filepath.Join(out, "converted.sarif")}); err != nil {
				t.Fatal(err)
			}
			sboms, err := filepath.Glob(filepath.Join(out, "*.cdx.json"))
			if err != nil || len(sboms) != 1 {
				t.Fatalf("sboms: %v %v", sboms, err)
			}
			for _, multi := range []bool{false, true} {
				dst := filepath.Join(out, "matched.json")
				args := []string{"match", "--db", db, "--format", "json", "-o", dst, sboms[0]}
				if multi {
					args = append(args, sboms[0])
				}
				if err := run(context.Background(), args); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(dst)
				if err != nil {
					t.Fatal(err)
				}
				if multi {
					var docs []json.RawMessage
					if err := json.Unmarshal(data, &docs); err != nil || len(docs) != 2 {
						t.Fatalf("multi: %v", err)
					}
					for _, doc := range docs {
						checkFindingsDocument(t, doc)
					}
				} else {
					checkFindingsDocument(t, data)
				}
			}
		})
	}
}

func TestReportFromRejectsLegacyAndUnknownSchema(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{`{"Findings":[]}`, "legacy findings JSON from a pre-release build; re-run bscan match"},
		{`{"schema":"bscan-findings/99","findings":[]}`, "unsupported findings schema"},
	} {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.html")
		if err := os.WriteFile(src, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		err := cmdReport(context.Background(), []string{"--from", src, "-o", dst})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("error = %v", err)
		}
		data, err := os.ReadFile(dst)
		if err != nil || string(data) != "keep" {
			t.Fatal("failed import replaced output")
		}
	}
}
