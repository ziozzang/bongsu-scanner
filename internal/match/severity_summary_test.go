package match

import (
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestDistroSeveritySummary(t *testing.T) {
	for _, prefix := range []string{"ALSA-", "RLSA-", "RHSA-", "USN-", "DSA-", "DLA-"} {
		for _, tc := range []struct{ summary, want string }{
			{"Critical: tar security update", "critical"},
			{"IMPORTANT: tar security update", "high"},
			{"mOdErAtE: tar security update", "medium"},
			{"Low: tar security update", "low"},
			{"Moderate tar security update", ""},
			{"tar: Moderate: security update", ""},
			{"High: tar security update", ""},
			{"Red Hat Security Advisory: RHSA-2026:0002", ""},
		} {
			t.Run(prefix+tc.summary, func(t *testing.T) {
				rec := vulndb.Record{ID: prefix + "2026:0002", Summary: tc.summary}
				if got := distroSeverity(rec, vulndb.Affected{}); got != tc.want {
					t.Fatalf("distro severity = %q, want %q", got, tc.want)
				}
			})
		}
	}
	for _, id := range []string{"CVE-2025-45582", "GHSA-example", "ALBA-2026:0002", "ALEA-2026:0002", "RXSA-2026:0002"} {
		if got := distroSeverity(vulndb.Record{ID: id, Summary: "Moderate: tar security update"}, vulndb.Affected{}); got != "" {
			t.Errorf("unscoped summary for %s: %q", id, got)
		}
	}
}

func TestAlmaLinuxSummarySeverityPolicy(t *testing.T) {
	rec := vulndb.Record{ID: "ALSA-2026:0002", Summary: "Moderate: tar security update"}
	for _, hasCVSS := range []bool{false, true} {
		wantCVSS := "UNKNOWN"
		if hasCVSS {
			rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
			wantCVSS = "CRITICAL"
		}
		cvss, _, _ := severity(rec, vulndb.Affected{})
		distro := distroSeverity(rec, vulndb.Affected{})
		for _, policy := range []string{"distro", "cvss", "max"} {
			want := wantCVSS
			if policy == "distro" || policy == "max" && !hasCVSS {
				want = "MEDIUM"
			}
			if got := selectedSeverity(cvss, distro, policy); got != want {
				t.Errorf("CVSS=%v policy=%s: got %s, want %s", hasCVSS, policy, got, want)
			}
		}
	}
	// Existing explicit vendor metadata retains precedence over the title.
	rec.Database = map[string]any{"severity": "Low"}
	if got := distroSeverity(rec, vulndb.Affected{}); got != "low" {
		t.Errorf("database precedence: %q", got)
	}
	rec.Database = nil
	rec.Severity = []vulndb.Severity{{Type: "vendor", Score: "Important"}}
	if got := distroSeverity(rec, vulndb.Affected{}); got != "high" {
		t.Errorf("structured precedence: %q", got)
	}
}
