package match

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestDefaultDistroMappingAndFallback(t *testing.T) {
	for _, tc := range []struct{ urgency, want string }{
		{"unimportant", "NEGLIGIBLE"}, {"low", "LOW"}, {"medium", "MEDIUM"}, {"high", "HIGH"},
		{"emergency", "CRITICAL"}, {"critical", "CRITICAL"}, {"not yet assigned", "MEDIUM"},
		{"end-of-life", "MEDIUM"}, {"", "MEDIUM"}, {"unknown", "MEDIUM"}, {" Emergency ", "CRITICAL"},
	} {
		for _, source := range []string{"", "distro", "cvss", "max"} {
			t.Run(tc.urgency+"/"+source, func(t *testing.T) {
				rec := advisory("Debian:13", "glibc", "2.0")
				rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "5.0"}}
				rec.Affected[0].Database = map[string]any{"urgency": tc.urgency}
				opts := Options{SeveritySource: source}
				run := func() Report {
					t.Helper()
					r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, opts)
					if err != nil {
						t.Fatal(err)
					}
					return r
				}
				want := tc.want
				if source == "cvss" || source == "max" && SeverityRank(want) < SeverityRank("MEDIUM") {
					want = "MEDIUM"
				}
				r := run()
				if len(r.Findings) != 1 {
					t.Fatalf("missing default finding: %+v", r)
				}
				f := r.Findings[0]
				if f.Severity != want || f.DistroSeverity != strings.ToLower(strings.TrimSpace(tc.urgency)) || f.Score != 5 || r.BySeverity[want] != 1 {
					t.Fatalf("got %+v, want %s with original score and urgency", f, want)
				}
				if ShouldFail(r, "HIGH") != (SeverityRank(want) >= SeverityRank("HIGH")) {
					t.Fatal("fail-on ignored policy")
				}
				opts.MinSeverity = "HIGH"
				if got := run(); (len(got.Findings) == 1) != (SeverityRank(want) >= SeverityRank("HIGH")) {
					t.Fatalf("min-severity ignored policy: %+v", got)
				}
			})
		}
	}
}

func TestSeverityPolicyMatchLegends(t *testing.T) {
	for _, tc := range []struct{ source, legend string }{
		{"", "Severity policy: distro (vendor rating first, CVSS fallback)"},
		{"cvss", "Severity policy: cvss"}, {"max", "Severity policy: max"},
	} {
		r, err := Run(context.Background(), &fakeStore{}, nil, Options{SeveritySource: tc.source})
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"table", "json", "cyclonedx"} {
			var b bytes.Buffer
			if err := Write(&b, format, r, Document{}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), tc.legend) {
				t.Errorf("%s/%s missing %q: %s", tc.source, format, tc.legend, &b)
			}
		}
	}
}

func TestUnimportantOptionsAndEmergencyMerge(t *testing.T) {
	rec := advisory("Debian:13", "glibc", "2.0")
	rec.Affected[0].Database = map[string]any{"urgency": "unimportant"}
	for _, include := range []bool{false, true} {
		for _, exclude := range []bool{false, true} {
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{IncludeUnimportant: include, ExcludeUnimportant: exclude})
			if err != nil || (len(r.Findings) == 1) == exclude || (r.Skipped["unimportant"] > 0) != exclude {
				t.Fatalf("include=%v exclude=%v: %+v %v", include, exclude, r, err)
			}
		}
	}
	rec.Affected[0].Database["urgency"] = "high"
	other := advisory("Debian:13", "glibc", "2.0")
	other.Affected[0].Database = map[string]any{"urgency": "emergency"}
	for _, records := range [][]vulndb.Record{{rec, other}, {other, rec}} {
		r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{distroSubject()}, Options{})
		if err != nil || len(r.Findings) != 1 || r.Findings[0].Severity != "CRITICAL" || r.Findings[0].DistroSeverity != "emergency" {
			t.Fatalf("emergency merge: %+v %v", r, err)
		}
	}
}
