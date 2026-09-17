package match

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func r18CVEMap(eco string, ids []string, rating string) map[string]any {
	cves := make([]any, 0, len(ids))
	for _, id := range ids {
		cves = append(cves, map[string]any{"id": id, "severity": []any{map[string]any{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}, map[string]any{"type": "Ubuntu", "score": rating}}})
	}
	return map[string]any{"cves_map": map[string]any{"ecosystem": eco, "cves": cves}}
}

func TestR18UbuntuReleaseCVEs(t *testing.T) {
	ids := []string{"CVE-2026-19542", "CVE-2026-6368", "CVE-2026-6791", "CVE-2026-77117", "CVE-2026-80489", "CVE-2026-19499"}
	for _, absent := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			usn := advisory("Ubuntu:22.04:LTS", "glibc", "3.0")
			usn.ID, usn.Aliases = "USN-8737-1", slices.Clone(ids)
			for _, id := range ids {
				usn.Aliases = append(usn.Aliases, "UBUNTU-"+id)
			}
			usn.Affected[0].Database = r18CVEMap("Ubuntu:22.04:LTS", ids[:5], "medium")
			usn.Affected[0].Specific = map[string]any{"ubuntu_priority": "critical"}
			noble := advisory("Ubuntu:24.04:LTS", "glibc", "3.0").Affected[0]
			noble.Database = r18CVEMap("Ubuntu:24.04:LTS", ids, "low")
			usn.Affected = append(usn.Affected, noble)
			companion := advisory("Ubuntu:22.04:LTS", "glibc", "3.0")
			companion.ID, companion.Aliases = "UBUNTU-"+ids[5], []string{ids[5]}
			companion.Affected[0].Ranges = nil
			companion.Affected[0].Database = map[string]any{"debian_status": "not-affected"}
			if absent {
				companion.Affected[0].Ecosystem = "Ubuntu:26.04:LTS"
			}
			subjects := []Subject{{Ref: "jammy", Name: "glibc", Ecosystem: "Ubuntu", Release: "22.04", Version: "2.0"}, {Ref: "noble", Name: "glibc", Ecosystem: "Ubuntu", Release: "24.04", Version: "2.0"}}
			if reverse {
				slices.Reverse(subjects)
			}
			report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{usn, companion}}, subjects, Options{})
			if err != nil || len(report.Findings) != 2 {
				t.Fatalf("absent=%v reverse=%v: %+v %v", absent, reverse, report, err)
			}
			for _, f := range report.Findings {
				wantIDs, wantRating := append([]string{usn.ID}, ids...), "low"
				if f.Subject.Ref == "jammy" {
					wantIDs, wantRating = append([]string{usn.ID}, ids[:5]...), "medium"
				}
				if !reflect.DeepEqual(f.RelatedIDs, unique(wantIDs)) || !reflect.DeepEqual(unique(f.Record.Aliases), unique(wantIDs[1:])) || f.DistroSeverity != wantRating || f.Severity != normalizeSeverity(wantRating) {
					t.Fatalf("release data leaked: %+v", f)
				}
			}
		}
	}
}

func TestR18UbuntuScopedAliasGrouping(t *testing.T) {
	ids := []string{"CVE-2026-1000", "CVE-2026-2000"}
	usn := advisory("Ubuntu:22.04:LTS", "glibc", "3.0")
	usn.ID, usn.Aliases = "USN-1-1", ids
	usn.Affected[0].Database = r18CVEMap("Ubuntu:22.04:LTS", ids[:1], "low")
	other := advisory("Ubuntu:24.04:LTS", "glibc", "3.0").Affected[0]
	other.Database = r18CVEMap(other.Ecosystem, ids[1:], "medium")
	usn.Affected = append(usn.Affected, other)
	for _, reverse := range []bool{false, true} {
		records := []vulndb.Record{usn}
		for i, release := range []string{"22.04", "24.04"} {
			cve := advisory("Ubuntu:"+release+":LTS", "glibc", "3.0")
			cve.ID, cve.Aliases = "UBUNTU-"+ids[i], []string{ids[i]}
			records = append(records, cve)
		}
		subjects := []Subject{{Ref: "jammy", Name: "glibc", Ecosystem: "Ubuntu", Release: "22.04", Version: "2.0"}, {Ref: "noble", Name: "glibc", Ecosystem: "Ubuntu", Release: "24.04", Version: "2.0"}}
		if reverse {
			slices.Reverse(subjects)
			slices.Reverse(records)
		}
		report, err := Run(context.Background(), &fakeStore{records: records}, subjects, Options{})
		if err != nil || len(report.Findings) != 2 {
			t.Fatalf("scoped grouping: %+v %v", report, err)
		}
		for _, f := range report.Findings {
			want := ids[0]
			if f.Subject.Ref == "noble" {
				want = ids[1]
			}
			if f.ID != want {
				t.Fatalf("wrong canonical ID: %+v", f)
			}
		}
	}
}

func TestR18VersionedNotAffected(t *testing.T) {
	for _, eco := range []string{"Red Hat", "Debian"} {
		for _, ranged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ranges=%v", eco, ranged), func(t *testing.T) {
				key := "redhat_status"
				if eco == "Debian" {
					key = "debian_status"
				}
				fixed, old, newer := "2.4.0-1.el9_8", "2.3.1-4.el9", "2.5.0-1.el9_8"
				if eco == "Debian" {
					fixed, old, newer = "2.4.0-1", "2.3.1-4", "2.5.0-1"
				}
				positive := advisory(eco+":9", "acl", fixed)
				marker := vulndb.Affected{Ecosystem: eco + ":9", Package: "acl", Versions: []string{"0:" + fixed}, Database: map[string]any{key: "not-affected"}}
				if ranged {
					marker.Ranges = []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}}}}
				}
				positive.Affected = append(positive.Affected, marker)
				subjects := []Subject{{Ref: "old", Name: "acl", Ecosystem: eco, Release: "9", Version: old}, {Ref: "fixed", Name: "acl", Ecosystem: eco, Release: "9", Version: fixed}, {Ref: "newer", Name: "acl", Ecosystem: eco, Release: "9", Version: newer}}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{positive}}, subjects, Options{})
				if err != nil || len(r.Findings) != 1 || r.Findings[0].Subject.Ref != "old" {
					t.Fatalf("version scope lost: %+v %v", r, err)
				}
				// Keep the positive range open across the excluded EVR to prove
				// the marker itself suppresses it, including a zero epoch alias.
				positive.Affected[0].Ranges = []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}}}}
				r, err = Run(context.Background(), &fakeStore{records: []vulndb.Record{positive}}, subjects, Options{})
				if err != nil || len(r.Findings) != 2 {
					t.Fatalf("exact marker suppression: %+v %v", r, err)
				}
				for _, f := range r.Findings {
					if f.Subject.Ref == "fixed" {
						t.Fatalf("listed EVR was not suppressed: %+v", f)
					}
				}
			})
		}
	}
}

func TestR18UbuntuEmptyCVEMapAndIgnoredAlias(t *testing.T) {
	for _, ids := range [][]string{nil, {"CVE-2026-1000"}} {
		rec := advisory("Ubuntu:22.04:LTS", "glibc", "3.0")
		rec.ID, rec.Aliases = "USN-1-1", []string{"CVE-2026-1000", "CVE-2026-2000"}
		rec.Affected[0].Database = r18CVEMap(rec.Affected[0].Ecosystem, ids, "low")
		r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{{Ref: "jammy", Name: "glibc", Ecosystem: "Ubuntu", Release: "22.04", Version: "2.0"}}, Options{IgnoreIDs: []string{"CVE-2026-2000"}})
		if err != nil || len(r.Findings) != 1 {
			t.Fatalf("unrelated ignored alias removed hit: %+v %v", r, err)
		}
		if !reflect.DeepEqual(r.Findings[0].RelatedIDs, unique(append([]string{rec.ID}, ids...))) {
			t.Fatalf("global aliases restored: %+v", r.Findings)
		}
	}
}

func TestR18UbuntuCVESeverity(t *testing.T) {
	for _, ratings := range [][]string{{"negligible", "low", "medium"}, {"medium", "low", "negligible"}} {
		a := vulndb.Affected{Ecosystem: "Ubuntu:22.04:LTS", Specific: map[string]any{"ubuntu_priority": "critical"}}
		var cves []any
		for i, rating := range ratings {
			mapped := r18CVEMap(a.Ecosystem, []string{fmt.Sprintf("CVE-2026-%04d", 1000+i)}, rating)
			cves = append(cves, mapped["cves_map"].(map[string]any)["cves"].([]any)...)
		}
		a.Database = map[string]any{"cves_map": map[string]any{"ecosystem": a.Ecosystem, "cves": cves}}
		if got := distroSeverity(vulndb.Record{}, a); got != "medium" {
			t.Fatalf("mapped severity=%q", got)
		}
	}
}
