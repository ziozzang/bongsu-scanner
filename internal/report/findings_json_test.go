package report

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestFindingsSchemaValidation(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`{"Findings":[]}`, "legacy findings JSON from a pre-release build; re-run bscan match"},
		{`{"findings":[]}`, "legacy findings JSON"},
		{`{"Schema":"bscan-findings/1","findings":[]}`, "legacy findings JSON"},
		{`{"schema":"bscan-findings/2","findings":[]}`, "unsupported findings schema"},
		{`{"schema":null,"findings":[]}`, "unsupported findings schema"},
		{`{"schema":1,"findings":[]}`, "findings schema"},
		{`{"schema":"bscan-findings/1","Findings":[]}`, "expected a findings array"},
		{`{"schema":"bscan-findings/1","findings":null}`, "expected a findings array"},
		{`{"schema":"bscan-findings/1","findings":{}}`, "expected a findings array"},
	} {
		_, err := LoadMatchJSON(strings.NewReader(tc.input))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %s", tc.input, err, tc.want)
		}
	}
	if _, err := LoadMatchJSON(strings.NewReader(`{"schema":"bscan-findings/1","findings":[],"future":true}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentedFindingsExample(t *testing.T) {
	data, err := os.ReadFile("../../docs/findings-json.md")
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(data), "```json\n")
	if !ok {
		t.Fatal("missing JSON example")
	}
	example, _, ok = strings.Cut(example, "\n```")
	if !ok {
		t.Fatal("unterminated JSON example")
	}
	r, err := LoadMatchJSON(strings.NewReader(example))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Matched != 1 || r.BySeverity["UNKNOWN"] != 1 || r.Findings[0].Subject.PURL.String() == "" {
		t.Fatalf("inconsistent example: %+v", r)
	}
	for _, format := range []string{"html", "markdown", "csv", "sarif"} {
		var out bytes.Buffer
		if err := Render(&out, format, Input{Report: r}); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(out.String(), r.Findings[0].ID) {
			t.Errorf("%s lost finding", format)
		}
	}
}
