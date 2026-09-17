package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/match"
)

func FuzzLoadMatchJSON(f *testing.F) {
	report := match.Report{Subjects: 2, Matched: 1, Skipped: map[string]int{"no-version": 1}, BySeverity: map[string]int{"HIGH": 1},
		Findings: []match.Finding{{ID: "CVE-2024-1234", RelatedIDs: []string{"GHSA-xxxx-yyyy-zzzz"}, Severity: "HIGH", Score: 8.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", MatchedBy: "purl", FixedIn: []string{"4.17.21"}, Confidence: "high",
			Subject: match.Subject{Ref: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20", Type: "npm", Ecosystem: "npm", Properties: map[string]string{"bscan:source": "package-lock.json"}}}}}
	good, _ := json.Marshal(report)
	f.Add(good)
	f.Add([]byte(`{"Findings":null,"Subjects":0,"extra_future_field":{"x":[1,2,3]}}`))
	f.Add([]byte(`{"findings":[{"ID":"CVE-1-1","Score":"not a number"}]}`))
	f.Add([]byte(`{"report_schema_version":1,"Findings":[]}`))
	f.Add([]byte(`{"Subjects":1}`))
	f.Add([]byte(`[{"Findings":[]}]`))
	f.Add([]byte(`{"Findings":[]}{"Findings":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"Findings":[{"Assessment":{"summary":"[31mred[0m"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := LoadMatchJSON(bytes.NewReader(data))
		if err != nil {
			if !strings.HasPrefix(err.Error(), "read match JSON:") && !strings.HasPrefix(err.Error(), "expected ") {
				t.Fatalf("unexpected error shape: %v", err)
			}
			return
		}
		// A loaded report must render in every format without panicking.
		for _, format := range []string{"json", "markdown", "csv", "sarif", "html"} {
			var out bytes.Buffer
			if err := Render(&out, format, Input{Report: r, Target: "fuzz", ToolVersion: "test"}); err != nil {
				t.Fatalf("Render(%s): %v", format, err)
			}
			if bytes.ContainsRune(out.Bytes(), 0x1b) && format != "json" {
				t.Fatalf("Render(%s) leaked an escape sequence", format)
			}
		}
		// Re-encoded output must load again.
		again, _ := json.Marshal(r)
		if _, err := LoadMatchJSON(bytes.NewReader(again)); err != nil {
			t.Fatalf("re-encoded report does not load: %v", err)
		}
	})
}
