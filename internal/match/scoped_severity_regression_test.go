package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestDistroMetadataRequiresMatchingEntry(t *testing.T) {
	for _, source := range []string{"", "cvss", "distro", "max"} {
		for _, kind := range []string{"range", "versions", "marker"} {
			for _, status := range []string{"", "undetermined", "not-affected"} {
				if kind == "marker" && status == "not-affected" {
					continue // A pure not-affected marker intentionally suppresses hits.
				}
				for _, versionsHit := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/versions=%v", source, kind, status, versionsHit), func(t *testing.T) {
						rec := advisory("Debian:13", "glibc", "2.0")
						rec.Affected[0].Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
						if versionsHit {
							rec.Affected[0].Ranges = nil
							rec.Affected[0].Versions = []string{"1.0"}
						}
						other := vulndb.Affected{Ecosystem: "Debian:13", Package: "glibc", Database: map[string]any{"urgency": "unimportant", "debian_status": status}}
						switch kind {
						case "range":
							other.Ranges = advisory("Debian:13", "glibc", "0.5").Affected[0].Ranges
						case "versions":
							other.Versions = []string{"0.5"}
						}
						rec.Affected = append([]vulndb.Affected{other}, rec.Affected...)
						r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{SeveritySource: source})
						if err != nil || len(r.Findings) != 1 {
							t.Fatalf("positive hit lost: %+v, %v", r, err)
						}
						f := r.Findings[0]
						if f.Subject.Ref != distroSubject().Ref || f.ID != rec.ID || f.Severity != "CRITICAL" || f.Score != 9.8 || f.DistroSeverity == "unimportant" {
							t.Fatalf("unrelated urgency changed hit: %+v", f)
						}
						wantStatus, wantConfidence := "", "high"
						if kind == "marker" && status == "undetermined" {
							wantStatus, wantConfidence = "undetermined", "low"
						}
						if f.DistroStatus != wantStatus || f.Confidence != wantConfidence {
							t.Fatalf("status scope: %+v", f)
						}
					})
				}
			}
		}
	}
}

func TestDistroNotAffectedSuppressesExplicitVersions(t *testing.T) {
	for _, layout := range []string{"same-record", "duplicate", "alias"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%v", layout, reverse), func(t *testing.T) {
				rec := advisory("Debian:13", "glibc", "2.0")
				rec.Affected[0].Ranges = nil
				rec.Affected[0].Versions = []string{"1.0"}
				marker := vulndb.Record{ID: rec.ID, Affected: []vulndb.Affected{{Ecosystem: "Debian:13", Package: "glibc", Database: map[string]any{"debian_status": "not-affected"}}}}
				records := []vulndb.Record{rec, marker}
				if reverse {
					records[0], records[1] = records[1], records[0]
				}
				if layout == "same-record" {
					records[0].Affected = append(records[0].Affected, records[1].Affected...)
					records = records[:1]
				} else if layout == "alias" {
					records[0].ID = "TRACKER-1"
					records[0].Aliases = []string{rec.ID}
				}
				r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{distroSubject()}, Options{})
				if err != nil || len(r.Findings) != 0 || r.Skipped["distro-not-affected"] != 1 {
					t.Fatalf("versions hit escaped marker: %+v, %v", r, err)
				}
			})
		}
	}
}

func TestNumericCVSSSeverity(t *testing.T) {
	for _, typ := range []string{"CVSS_V2", "CVSS_V3", "CVSS_V4"} {
		for _, tc := range []struct {
			raw, level string
			score      float64
		}{
			{"0", "NEGLIGIBLE", 0}, {"0.1", "LOW", 0.1}, {"3.9", "LOW", 3.9},
			{"4.0", "MEDIUM", 4}, {"6.9", "MEDIUM", 6.9}, {"7.0", "HIGH", 7},
			{"8.9", "HIGH", 8.9}, {"9.0", "CRITICAL", 9}, {"9.8", "CRITICAL", 9.8},
			{"10", "CRITICAL", 10}, {" 9.8 ", "CRITICAL", 9.8},
			{"-1", "UNKNOWN", 0}, {"10.1", "UNKNOWN", 0}, {"NaN", "UNKNOWN", 0}, {"+Inf", "UNKNOWN", 0},
		} {
			t.Run(typ+"/"+tc.raw, func(t *testing.T) {
				for _, affected := range []bool{false, true} {
					r := vulndb.Record{Severity: []vulndb.Severity{{Type: typ, Score: tc.raw}}}
					a := vulndb.Affected{}
					if affected {
						a.Severity, r.Severity = r.Severity, nil
					}
					for _, parse := range []func(vulndb.Record, vulndb.Affected) (string, float64, string){severity, newVersionCache().severity} {
						level, score, vector := parse(r, a)
						if level != tc.level || score != tc.score || vector != "" {
							t.Fatalf("affected=%v: got %s/%g/%q, want %s/%g/empty vector", affected, level, score, vector, tc.level, tc.score)
						}
					}
				}
			})
		}
	}
}

func TestNumericCVSSMaximum(t *testing.T) {
	for _, typ := range []string{"CVSS_V2", "CVSS_V3", "CVSS_V4"} {
		vector := map[string]string{
			"CVSS_V2": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			"CVSS_V3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"CVSS_V4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		}[typ]
		for _, first := range []string{"2.0", "9.0", vector} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reverse=%v", typ, first, reverse), func(t *testing.T) {
					rec := advisory("Debian:13", "glibc", "2.0")
					rec.Severity = []vulndb.Severity{{Type: typ, Score: first}, {Type: typ, Score: "9.8"}}
					if reverse {
						rec.Severity[0], rec.Severity[1] = rec.Severity[1], rec.Severity[0]
					}
					rec.Affected[0].Database = map[string]any{"urgency": "high"}
					r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{distroSubject()}, Options{SeveritySource: "max"})
					if err != nil || len(r.Findings) != 1 {
						t.Fatalf("%+v, %v", r, err)
					}
					f := r.Findings[0]
					if f.Severity != "CRITICAL" || f.Score != 9.8 || f.Vector != "" || f.Record.Score != 9.8 || f.Record.Vector != "" {
						t.Fatalf("numeric maximum lost: %+v", f)
					}
				})
			}
		}
	}
}

func TestDistroMetadataScopeAcrossCachedVersions(t *testing.T) {
	for _, status := range []string{"", "not-affected", "undetermined"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%v", status, reverse), func(t *testing.T) {
				rec := advisory("Debian:13", "glibc", "2.0")
				rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
				tracker := advisory("Debian:13", "glibc", "0.5")
				tracker.ID, tracker.Aliases = "TRACKER-1", []string{rec.ID}
				tracker.Affected[0].Database = map[string]any{"urgency": "unimportant", "debian_status": status}
				subjects := []Subject{distroSubject(), distroSubject()}
				subjects[0].Ref, subjects[0].Version = "unimportant-version", "0.1"
				if reverse {
					subjects[0], subjects[1] = subjects[1], subjects[0]
				}
				store := &fakeStore{records: []vulndb.Record{tracker, rec}}
				r, err := Run(context.Background(), store, subjects, Options{SeveritySource: "max", ExcludeUnimportant: true})
				if err != nil || len(r.Findings) != 1 {
					t.Fatalf("cached scope: %+v, %v", r, err)
				}
				f := r.Findings[0]
				if f.Subject.Ref != distroSubject().Ref || f.ID != rec.ID || f.Severity != "CRITICAL" || f.DistroSeverity != "" || f.DistroStatus != "" || f.Confidence != "high" {
					t.Fatalf("metadata leaked between versions: %+v", f)
				}
				if store.calls != 2 { // One lookup each for the source and binary names.
					t.Fatalf("lookups = %d, want 2", store.calls)
				}
			})
		}
	}
}
