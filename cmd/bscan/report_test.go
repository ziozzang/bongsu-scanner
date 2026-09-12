package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/report"
)

func reportCLIInput(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := match.Write(&b, "json", match.Report{Subjects: 3, Matched: 1, Findings: []match.Finding{{ID: "CVE-2026-1", Severity: "HIGH", Subject: match.Subject{Name: "fixture", Version: "1"}}}}, match.Document{}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "match.json")
	if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestReportCLIFormatsAndContext(t *testing.T) {
	input := reportCLIInput(t)
	sbom := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"sbom-target","properties":[{"name":"bscan:scan:metadata-skipped","value":"5"},{"name":"bscan:scan:partial","value":"true"}]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"html", "markdown", "md", "json", "csv", "sarif"} {
		t.Run(format, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report."+format)
			err := run(context.Background(), []string{"report", "--from", input, "--sbom", sbom, "--format", format, "--title", "custom-title", "-o", out})
			if err != nil || exitCode(err) != 0 {
				t.Fatalf("err=%v", err)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte("custom-title")) {
				t.Fatal("title missing")
			}
			if format == "json" {
				var d report.Document
				if err := json.Unmarshal(b, &d); err != nil {
					t.Fatal(err)
				}
				if d.Scan == nil || d.Scan.MetadataSkipped != 5 || !d.Scan.Partial || d.Summary.Findings != 1 || d.GeneratedBy.Version != version {
					t.Fatal(d)
				}
			}
		})
	}
}
func TestReportCLIValidationAndAtomicOutput(t *testing.T) {
	input := reportCLIInput(t)
	out := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(out, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{}, {"--from", input, "--format", "bad"}, {"--from", input, "extra"}, {"--from", input, "--sbom", "/missing"}, {"--from", "/missing"}} {
		args = append(args, "-o", out)
		if err := cmdReport(context.Background(), args); exitCode(err) != 1 {
			t.Fatalf("args=%v err=%v", args, err)
		}
		b, err := os.ReadFile(out)
		if err != nil || string(b) != "keep" {
			t.Fatal("failed command damaged output")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cmdReport(ctx, []string{"--from", input, "-o", out}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	err := writeReportFile(out, func(w io.Writer) error { _, _ = io.WriteString(w, "partial"); return io.ErrClosedPipe })
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "keep" {
		t.Fatal("partial output published")
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp leak: %v %v", entries, err)
	}
	if err := cmdReport(context.Background(), []string{"--from", input, "--format", "json", "-o", input}); err != nil {
		t.Fatal("same path render:", err)
	}
}
func TestReportCLIStdoutAndHelp(t *testing.T) {
	input := reportCLIInput(t)
	old := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Stdout = f
	defer func() { os.Stdout = old }()
	if err := cmdReport(context.Background(), []string{"--from", input, "--format", "json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil || !strings.Contains(string(b), `"report_schema_version":1`) {
		t.Fatalf("stdout=%s err=%v", b, err)
	}
	if err := run(context.Background(), []string{"report", "--help"}); err != nil {
		t.Fatal(err)
	}
}
