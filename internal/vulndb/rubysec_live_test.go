package vulndb

import (
	"context"
	"os"
	"testing"
)

// Optional smoke test against an already downloaded upstream archive.
func TestRubysecLiveArchive(t *testing.T) {
	filename := os.Getenv("BONGSU_RUBYSEC_TEST_ARCHIVE")
	if filename == "" {
		t.Skip("set BONGSU_RUBYSEC_TEST_ARCHIVE to a downloaded RubySec ZIP")
	}
	count, targets := 0, 0
	err := parseRubysecZip(context.Background(), filename, func(r *Record) error {
		count++
		if r.ID == "CVE-2026-80212" || r.ID == "CVE-2026-80213" {
			targets++
			if len(r.Affected) != 1 || r.Affected[0].Package != "resolv" {
				t.Fatalf("unexpected resolv record: %+v", r)
			}
			rubysecAssertAffected(t, r.Affected[0], map[string]bool{"0.3.1": true, "0.3.2": false, "0.7.1": true, "0.7.2": false})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if targets != 2 {
		t.Fatalf("target advisories=%d, want 2", targets)
	}
	t.Logf("parsed %d advisories, checked %d resolv advisories", count, targets)
}
