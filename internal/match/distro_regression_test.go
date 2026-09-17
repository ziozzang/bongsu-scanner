package match

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func distroSubject() Subject {
	return Subject{Ref: "libc6", Name: "libc6", Upstream: "glibc", Type: "deb", Ecosystem: "Debian", Release: "13", Version: "1.0"}
}

func TestDistroMarkersAcrossDuplicates(t *testing.T) {
	for _, status := range []string{"not-affected", "undetermined"} {
		for _, reverse := range []bool{false, true} {
			t.Run(status+map[bool]string{false: "/osv-first", true: "/tracker-first"}[reverse], func(t *testing.T) {
				osv := advisory("Debian:13", "glibc", "2.0")
				osv.ID = "OSV-1"
				osv.Aliases = []string{"CVE-2026-1234"}
				tracker := vulndb.Record{ID: "CVE-2026-1234", Affected: []vulndb.Affected{{Ecosystem: "Debian:13", Package: "glibc", Database: map[string]any{"debian_status": status}}}}
				records := []vulndb.Record{osv, tracker}
				if reverse {
					records[0], records[1] = records[1], records[0]
				}
				r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{distroSubject()}, Options{})
				if err != nil {
					t.Fatal(err)
				}
				if status == "not-affected" {
					if len(r.Findings) != 0 || r.Skipped["distro-not-affected"] != 1 {
						t.Fatalf("not-affected: %+v", r)
					}
				} else if len(r.Findings) != 1 || r.Findings[0].Confidence != "low" || r.Skipped["no-usable-range"] != 0 {
					t.Fatalf("undetermined: %+v", r)
				}
			})
		}
	}
}

func TestDistroUrgencySourcesExcludeUnimportant(t *testing.T) {
	for _, source := range []string{"affected-database", "affected-specific", "record-database"} {
		t.Run(source, func(t *testing.T) {
			rec := advisory("Debian:13", "glibc", "2.0")
			urgency := map[string]any{"urgency": "unimportant"}
			switch source {
			case "affected-database":
				rec.Affected[0].Database = urgency
			case "affected-specific":
				rec.Affected[0].Specific = urgency
			case "record-database":
				rec.Database = urgency
			}
			for _, include := range []bool{false, true} {
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{IncludeUnimportant: include})
				if err != nil {
					t.Fatal(err)
				}
				if (len(r.Findings) == 1) != include {
					t.Fatalf("include=%v: %+v", include, r)
				}
			}
		})
	}
}

func TestDistroMarkerScope(t *testing.T) {
	for _, tc := range []struct{ name, eco, pkg, id, withdrawn string }{
		{name: "other release", eco: "Debian:12", pkg: "glibc", id: "CVE-2026-1234"},
		{name: "other package", eco: "Debian:13", pkg: "openssl", id: "CVE-2026-1234"},
		{name: "other ecosystem", eco: "Ubuntu:13", pkg: "glibc", id: "CVE-2026-1234"},
		{name: "other CVE", eco: "Debian:13", pkg: "glibc", id: "CVE-2026-9999"},
		{name: "withdrawn marker", eco: "Debian:13", pkg: "glibc", id: "CVE-2026-1234", withdrawn: "2026-01-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := advisory("Debian:13", "glibc", "2.0")
			marker := vulndb.Record{ID: tc.id, Withdrawn: tc.withdrawn, Affected: []vulndb.Affected{{Ecosystem: tc.eco, Package: tc.pkg, Database: map[string]any{"debian_status": "not-affected"}}}}
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{marker, rec}}, []Subject{distroSubject()}, Options{})
			if err != nil || len(r.Findings) != 1 || r.Findings[0].ID != rec.ID {
				t.Fatalf("marker leaked: %+v, %v", r, err)
			}
		})
	}
}

func TestDistroSeverityPolicies(t *testing.T) {
	for _, source := range []string{"affected-database", "affected-specific", "record-database"} {
		for _, urgency := range []string{"low", "medium", "high", "end-of-life", "not yet assigned"} {
			for _, mode := range []string{"", "cvss", "distro", "max"} {
				t.Run(source+"/"+urgency+"/"+mode, func(t *testing.T) {
					rec := advisory("Debian:13", "glibc", "2.0")
					rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
					data := map[string]any{"urgency": urgency}
					switch source {
					case "affected-database":
						rec.Affected[0].Database = data
					case "affected-specific":
						rec.Affected[0].Specific = data
					case "record-database":
						rec.Database = data
					}
					store := &fakeStore{records: []vulndb.Record{rec}}
					opts := Options{SeveritySource: mode}
					r, err := Run(context.Background(), store, []Subject{distroSubject()}, opts)
					if err != nil || len(r.Findings) != 1 {
						t.Fatalf("%+v %v", r, err)
					}
					want := "CRITICAL"
					if mode == "distro" {
						switch urgency {
						case "low":
							want = "LOW"
						case "medium":
							want = "MEDIUM"
						case "high":
							want = "HIGH"
						}
					}
					f := r.Findings[0]
					if f.Severity != want || f.DistroSeverity != urgency || f.Record.DistroSeverity != urgency || f.Score != 9.8 || r.BySeverity[want] != 1 {
						t.Fatalf("policy result: %+v", r)
					}
					if ShouldFail(r, "CRITICAL") != (want == "CRITICAL") {
						t.Fatalf("fail-on disagrees: %+v", r)
					}
					opts.MinSeverity = "CRITICAL"
					filtered, err := Run(context.Background(), store, []Subject{distroSubject()}, opts)
					if err != nil || (len(filtered.Findings) == 1) != (want == "CRITICAL") || filtered.Matched != len(filtered.Findings) || filtered.BySeverity["CRITICAL"] != len(filtered.Findings) {
						t.Fatalf("minimum disagrees: %+v %v", filtered, err)
					}
				})
			}
		}
	}
	// Max must also raise a lower CVSS level, and absent urgency must fall back.
	for _, urgency := range []string{"high", ""} {
		rec := advisory("Debian:13", "glibc", "2.0")
		rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "2.0"}}
		rec.Affected[0].Specific = map[string]any{"urgency": urgency}
		for _, mode := range []string{"distro", "max"} {
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{SeveritySource: mode})
			want := "LOW"
			if urgency != "" {
				want = "HIGH"
			}
			if err != nil || len(r.Findings) != 1 || r.Findings[0].Severity != want {
				t.Fatalf("%s/%s: %+v %v", mode, urgency, r, err)
			}
		}
	}
	if _, err := Run(context.Background(), &fakeStore{}, nil, Options{SeveritySource: "bogus"}); err == nil {
		t.Fatal("invalid severity source accepted")
	}
}

func TestDistroSeverityDuplicateAndErratum(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		rec := advisory("Debian:13", "glibc", "2.0")
		rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
		tracker := advisory("Debian:13", "glibc", "2.0")
		tracker.ID = "TRACKER-1"
		tracker.Aliases = []string{rec.ID}
		tracker.Affected[0].Database = map[string]any{"urgency": "low", "debian_status": "undetermined"}
		records := []vulndb.Record{rec, tracker}
		if reverse {
			records[0], records[1] = records[1], records[0]
		}
		r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{distroSubject()}, Options{SeveritySource: "distro"})
		if err != nil || len(r.Findings) != 1 {
			t.Fatalf("%+v %v", r, err)
		}
		f := r.Findings[0]
		if f.Severity != "LOW" || f.DistroSeverity != "low" || f.Confidence != "low" || f.DistroStatus != "undetermined" {
			t.Fatalf("merged: %+v", f)
		}
	}
	for _, prefix := range []string{"RLSA-", "ALSA-", "RHSA-", "USN-", "DSA-", "DLA-"} {
		rec := advisory("Debian:13", "glibc", "2.0")
		rec.ID = prefix + "2026-1"
		rec.Aliases = []string{"CVE-2026-1", "CVE-2026-2"}
		rec.Database = map[string]any{"severity": "Important"}
		rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
		r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{})
		if err != nil || len(r.Findings) != 1 || r.Findings[0].ID != rec.ID || r.Findings[0].DistroSeverity != "high" || r.Findings[0].Record.DistroSeverity != "high" {
			t.Fatalf("erratum: %+v %v", r, err)
		}
	}
}

func TestDistroMissingCoverageCollection(t *testing.T) {
	subjects := []Subject{
		{Ref: "a", Ecosystem: "Ubuntu", Release: "24.04", Name: "foo", Version: "1"},
		{Ref: "b", Ecosystem: "Ubuntu", Release: "24.04", Name: "bar", Version: "1"},
		{Ref: "c", Ecosystem: "Debian", Release: "12", Name: "foo", Version: "1"},
		{Ref: "d", Ecosystem: "Debian", Name: "foo", Version: "1"},
		{Ref: "e", Name: "unknown", Version: "1"},
	}
	r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Debian:13", "glibc", "2")}}, subjects, Options{})
	want := []string{"coverage gap: Debian:12 (1 subjects) — run bscan db update --ecosystem Debian", "coverage gap: Ubuntu:24.04 (2 subjects) — run bscan db update --ecosystem Ubuntu"}
	if err != nil || !reflect.DeepEqual(r.MissingCoverage, want) || r.Skipped["ecosystem-not-in-database"] != 2 || r.Skipped["release-not-in-database"] != 1 {
		t.Fatalf("coverage: %+v %v", r, err)
	}
}

func TestDistroMatchOutput(t *testing.T) {
	warning := "coverage gap: Ubuntu:24.04 (137 subjects) — run bscan db update --ecosystem Ubuntu"
	r := Report{MissingCoverage: []string{warning}, Findings: []Finding{{ID: "CVE-2026-1", DistroSeverity: "end-of-life", DistroStatus: "undetermined", Confidence: "low"}}}
	for _, format := range []string{"table", "json", "cyclonedx"} {
		var b bytes.Buffer
		if err := Write(&b, format, r, Document{}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{warning, "end-of-life", "undetermined"} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("%s missing %q: %s", format, want, &b)
			}
		}
		if format == "table" && !strings.Contains(b.String(), "DISTRO-STATUS") {
			t.Fatal("missing table columns")
		}
	}
}

func TestDistroMarkerWithRangeCountsSuppression(t *testing.T) {
	rec := advisory("Debian:13", "GLIBC", "2.0")
	rec.Affected[0].Database = map[string]any{"debian_status": "not-affected", "urgency": "unimportant"}
	r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{})
	if err != nil || len(r.Findings) != 0 || r.Skipped["distro-not-affected"] != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDistroMarkersRetainedAcrossVersionsAndReleases(t *testing.T) {
	rec := advisory("Debian:13", "glibc", "2.0")
	rec.Affected = append(rec.Affected, advisory("Debian:12", "glibc", "2.0").Affected...)
	marker := vulndb.Record{ID: rec.ID, Affected: []vulndb.Affected{{Ecosystem: "Debian:13", Package: " GLIBC ", Database: map[string]any{"debian_status": "not-affected"}, Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}, {Fixed: "0"}}}}}}}
	subjects := []Subject{distroSubject(), distroSubject(), distroSubject()}
	subjects[0].Version = "3.0" // a quiet range miss must not discard the marker
	subjects[1].Ref = "vulnerable-13"
	subjects[2].Ref = "vulnerable-12"
	subjects[2].Release = "12"
	r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec, marker}}, subjects, Options{})
	if err != nil || len(r.Findings) != 1 || r.Findings[0].Subject.Ref != "vulnerable-12" || r.Skipped["distro-not-affected"] != 1 {
		t.Fatalf("cached marker: %+v %v", r, err)
	}
}

func TestDistroUnimportantDuplicatePolicy(t *testing.T) {
	rec := advisory("Debian:13", "glibc", "2.0")
	tracker := advisory("Debian:13", "glibc", "2.0")
	tracker.ID = "TRACKER-1"
	tracker.Aliases = []string{rec.ID}
	tracker.Affected[0].Specific = map[string]any{"urgency": "unimportant"}
	for _, include := range []bool{false, true} {
		r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec, tracker}}, []Subject{distroSubject()}, Options{IncludeUnimportant: include})
		if err != nil || (len(r.Findings) == 1) != include {
			t.Fatalf("duplicate unimportant: %+v %v", r, err)
		}
		if include && r.Findings[0].DistroSeverity != "unimportant" {
			t.Fatalf("lost urgency: %+v", r)
		}
	}
}
