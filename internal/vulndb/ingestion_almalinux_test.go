package vulndb

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestAlmaLinuxIngestionRelatedCVEs(t *testing.T) {
	for _, tc := range []struct {
		id            string
		aliases, want []string
	}{
		{"ALSA-2026:0002", nil, []string{"CVE-2025-45582", "CVE-2025-45583"}},
		{"ALBA-2026:0002", nil, []string{"CVE-2025-45582", "CVE-2025-45583"}},
		{"ALEA-2026:0002", []string{"OTHER-1"}, []string{"OTHER-1", "CVE-2025-45582", "CVE-2025-45583"}},
		{"RLSA-2026:0002", nil, nil},
		{"GHSA-example", nil, nil},
		{"ALSA-2026:0003", []string{"CVE-2025-99999"}, []string{"CVE-2025-99999"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			spool, err := newIngestionSpool(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = spool.close() })
			related := []string{"CVE-2025-45582", "OTHER-2", "CVE-2025-45583", "CVE-2025-45582"}
			records := []Record{
				{ID: tc.id, Aliases: tc.aliases, Related: related, Affected: []Affected{{Ecosystem: "AlmaLinux:9", Package: "tar"}}},
				{ID: "CVE-2025-45582", Severity: []Severity{{Type: "CVSS_V3", Score: "9.8"}}},
			}
			for _, r := range records {
				b, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if err := spool.append(r.ID, append(b, '\n')); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.close(); err != nil {
				t.Fatal(err)
			}
			err = visitIngestionSpools(context.Background(), []*ingestionSpool{spool}, nil, time.Now(), func(r *Record) error {
				if r.ID != tc.id {
					return nil
				}
				if !slices.Equal(r.Aliases, tc.want) {
					t.Errorf("aliases = %v, want %v", r.Aliases, tc.want)
				}
				if !slices.Equal(r.Related, related) {
					t.Errorf("related changed: %v", r.Related)
				}
				if slices.Contains(tc.want, "CVE-2025-45582") {
					if !slices.Equal(r.Severity, records[1].Severity) || !slices.Equal(r.Affected[0].Severity, records[1].Severity) || r.Database["severity_source"] != "alias:CVE-2025-45582" {
						t.Errorf("alias CVSS not propagated: %+v", r)
					}
				} else if len(r.Severity) != 0 {
					t.Errorf("unrelated severity propagated: %+v", r)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
