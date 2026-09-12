package vulndb

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

const aliasCriticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func TestIngestionAliasSeverity(t *testing.T) {
	// Distinct IDs land in different spool partitions. A merged donor gains
	// its CVE alias from another feed, so indexing before merging is incorrect.
	for _, reverse := range []bool{false, true} {
		spools := make([]*ingestionSpool, 2)
		for i := range spools {
			var err error
			spools[i], err = newIngestionSpool(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
		}
		appendRecord := func(i int, r Record) {
			t.Helper()
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := spools[i].append(r.ID, append(b, '\n')); err != nil {
				t.Fatal(err)
			}
		}
		affected := []Affected{{Ecosystem: "Debian:13", Package: "demo"}, {Ecosystem: "Debian:12", Package: "demo", Severity: []Severity{{Type: "CVSS_V2", Score: "4.0"}}}}
		appendRecord(0, Record{ID: "DEBIAN-CVE-X", Aliases: []string{"CVE-X"}, Affected: affected, Database: map[string]any{"keep": "yes"}})
		appendRecord(0, Record{ID: "GHSA-Y", Severity: []Severity{{Type: "CVSS_V3", Score: aliasCriticalVector}}})
		appendRecord(1, Record{ID: "GHSA-Y", Aliases: []string{"CVE-X"}})
		for _, spool := range spools {
			if err := spool.close(); err != nil {
				t.Fatal(err)
			}
		}
		if reverse {
			spools[0], spools[1] = spools[1], spools[0]
		}
		var got *Record
		err := visitIngestionSpools(context.Background(), spools, nil, time.Now(), func(r *Record) error {
			if r.ID == "DEBIAN-CVE-X" {
				got = r
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := []Severity{{Type: "CVSS_V3", Score: aliasCriticalVector}}
		if got == nil || !reflect.DeepEqual(got.Severity, want) || !reflect.DeepEqual(got.Affected[0].Severity, want) || got.Database["severity_source"] != "alias:GHSA-Y" || got.Database["keep"] != "yes" {
			t.Fatalf("propagation: %+v", got)
		}
		if !reflect.DeepEqual(got.Affected[1].Severity, affected[1].Severity) {
			t.Fatal("existing affected severity changed")
		}
	}
}

func TestAliasSeverityPreferenceAndPreservation(t *testing.T) {
	records := []Record{
		{ID: "GHSA-Z", Aliases: []string{"CVE-X"}, Severity: []Severity{{Type: "CVSS_V4", Score: "v4-z"}}},
		{ID: "GHSA-A", Aliases: []string{"CVE-X"}, Affected: []Affected{{Severity: []Severity{{Type: "CVSS_V3", Score: aliasCriticalVector}, {Type: "CVSS_V4", Score: "v4-a"}}}}},
		{ID: "CVE-X", Severity: []Severity{{Type: "CVSS_V2", Score: "10"}}},
		{ID: "GHSA-B", Aliases: []string{"CVE-X"}, Severity: []Severity{{Type: "CVSS_V3", Score: aliasCriticalVector}}},
	}
	for range 20 {
		index := aliasSeverityIndex{}
		// Map iteration forces varying insertion order.
		candidates := map[int]Record{}
		for i, r := range records {
			candidates[i] = r
		}
		for _, r := range candidates {
			index.add(&r)
		}
		r := Record{ID: "DEBIAN-CVE-X", Aliases: []string{"CVE-X"}}
		index.apply(&r)
		if r.Database["severity_source"] != "alias:GHSA-A" || len(r.Severity) != 2 || r.Severity[0].Type != "CVSS_V4" {
			t.Fatalf("best candidate: %+v", r)
		}
		r.Severity[0].Score = "changed"
		if index["CVE-X"].severity[0].Score == "changed" {
			t.Fatal("severity slices shared")
		}
		original := Record{ID: "CVE-X", Severity: []Severity{{Type: "CVSS_V2", Score: "3"}}, Affected: []Affected{{Package: "demo"}}}
		index.apply(&original)
		if original.Severity[0].Score != "3" || original.Database != nil || len(original.Affected[0].Severity) != 0 {
			t.Fatal("existing effective severity overwritten")
		}
		unknown := Record{ID: "CVE-UNKNOWN"}
		index.apply(&unknown)
		if len(unknown.Severity) != 0 || unknown.Database != nil {
			t.Fatal("unrelated CVE received severity")
		}
	}
}
