package report

import (
	"bytes"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/match"
)

func TestSeverityPolicyLegends(t *testing.T) {
	for _, tc := range []struct{ source, legend string }{
		{"", "Severity policy: distro (vendor rating first, CVSS fallback)"},
		{"distro", "Severity policy: distro (vendor rating first, CVSS fallback)"},
		{"cvss", "Severity policy: cvss"}, {"max", "Severity policy: max"},
	} {
		for _, format := range []string{"html", "markdown", "json", "csv", "sarif"} {
			for _, empty := range []bool{false, true} {
				in := fixture()
				in.Options = match.Options{SeveritySource: tc.source}
				if empty {
					in.Report.Findings = nil
				}
				b := renderTest(t, format, in)
				if !bytes.Contains(b, []byte(tc.legend)) {
					t.Errorf("%s/%s/empty=%v missing %q", tc.source, format, empty, tc.legend)
				}
			}
		}
	}
}

func TestUnimportantFilterLegend(t *testing.T) {
	in := fixture()
	in.Options = match.Options{SeveritySource: "distro", IncludeUnimportant: true, ExcludeUnimportant: true}
	for _, format := range []string{"html", "markdown"} {
		b := renderTest(t, format, in)
		if !bytes.Contains(b, []byte("exclude-unimportant")) || bytes.Contains(b, []byte("include-unimportant")) {
			t.Errorf("%s: obsolete or missing filter legend", format)
		}
	}
	in.Options = match.Options{}
	for _, format := range []string{"html", "markdown", "json", "csv", "sarif"} {
		if b := renderTest(t, format, in); !bytes.Contains(b, []byte("default policy shown, original matching policy unknown")) {
			t.Errorf("%s: caller omitted policy but legend claims it is known", format)
		}
	}
}
