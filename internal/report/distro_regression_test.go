package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/match"
)

func TestDistroFieldsAndCoverageAllFormats(t *testing.T) {
	warning := "coverage gap: Ubuntu:24.04 (137 subjects) — run bscan db update --ecosystem Ubuntu"
	in := Input{Report: match.Report{MissingCoverage: []string{warning}, Findings: []match.Finding{{ID: "CVE-2026-1", Severity: "CRITICAL", DistroSeverity: "end-of-life", DistroStatus: "undetermined", Confidence: "low"}}}}
	for _, format := range []string{"html", "markdown", "csv", "sarif", "json"} {
		t.Run(format, func(t *testing.T) {
			b := renderTest(t, format, in)
			for _, want := range []string{warning, "end-of-life", "undetermined"} {
				if !bytes.Contains(b, []byte(want)) {
					t.Errorf("missing %q: %s", want, b)
				}
			}
			switch format {
			case "html", "markdown", "csv":
				for _, column := range []string{"Distro severity", "Distro status"} {
					if !bytes.Contains(b, []byte(column)) {
						t.Errorf("missing column %q", column)
					}
				}
			case "sarif", "json":
				for _, key := range []string{`"distro_severity":"end-of-life"`, `"distro_status":"undetermined"`, `"missing_coverage"`} {
					if !bytes.Contains(b, []byte(key)) {
						t.Errorf("missing key %s", key)
					}
				}
			}
			if format == "csv" {
				rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				for i, c := range rows[0] {
					if c == "Distro severity" && rows[1][i] != "end-of-life" || c == "Distro status" && rows[1][i] != "undetermined" {
						t.Fatalf("columns misaligned: %v", rows)
					}
				}
			}
			empty := in
			empty.Report.Findings = nil
			if output := renderTest(t, format, empty); !bytes.Contains(output, []byte(warning)) {
				t.Fatalf("no-findings coverage lost: %s", output)
			}
		})
	}
	// A match JSON round trip must retain the fields used by `report --from`.
	raw, err := json.Marshal(in.Report)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMatchJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	in.Report = loaded
	if output := renderTest(t, "markdown", in); !strings.Contains(string(output), "undetermined") || !strings.Contains(string(output), warning) {
		t.Fatalf("round trip: %s", output)
	}
}
