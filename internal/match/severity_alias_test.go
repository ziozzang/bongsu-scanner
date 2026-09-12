package match

import (
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"testing"
)

func TestAliasPropagatedSeverityRating(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	record := vulndb.Record{ID: "DEBIAN-CVE-X", Aliases: []string{"CVE-X"}, Severity: []vulndb.Severity{{Type: "CVSS_V3", Score: vector}}, Database: map[string]any{"severity_source": "alias:GHSA-Y"}}
	level, score, got := severity(record, vulndb.Affected{})
	if level != "CRITICAL" || score != 9.8 || got != vector {
		t.Fatalf("rating = %s/%g/%s", level, score, got)
	}
	record.Severity = nil
	level, score, got = severity(record, vulndb.Affected{})
	if level != "UNKNOWN" || score != 0 || got != "" {
		t.Fatalf("missing score invented: %s/%g/%s", level, score, got)
	}
}
