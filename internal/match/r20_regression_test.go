package match

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func r20UbuntuQueries(binaryFixed string) (vulndb.Record, Subject) {
	rec := advisory("Ubuntu:22.04:LTS", "src", "3.0")
	rec.ID, rec.Aliases = "USN-1-1", []string{"CVE-2026-1000", "CVE-2026-2000"}
	rec.Affected[0].Database = r18CVEMap(rec.Affected[0].Ecosystem, rec.Aliases[:1], "medium")
	bin := advisory("Ubuntu:22.04:LTS", "bin", binaryFixed).Affected[0]
	bin.Database = r18CVEMap(bin.Ecosystem, rec.Aliases[1:], "low")
	rec.Affected = append(rec.Affected, bin)
	return rec, Subject{Ref: "bin", Name: "bin", Version: "2.0", Upstream: "src", Type: "deb", Ecosystem: "Ubuntu", Release: "22.04"}
}

func TestR20WrongCanonicalSuppressesSourceCVE(t *testing.T) {
	for _, markerID := range []string{"", "CVE-2026-2000", "CVE-2026-1000"} {
		for _, ignoreID := range []string{"", "CVE-2026-2000", "CVE-2026-1000", "USN-1-1"} {
			t.Run(markerID+"/ignore="+ignoreID, func(t *testing.T) {
				rec, subject := r20UbuntuQueries("1.0")
				records := []vulndb.Record{rec}
				if markerID != "" {
					marker := advisory("Ubuntu:22.04:LTS", "src", "3.0")
					marker.ID, marker.Aliases = "UBUNTU-"+markerID, []string{markerID}
					marker.Affected[0].Ranges = nil
					marker.Affected[0].Database = map[string]any{"debian_status": "not-affected"}
					records = append(records, marker)
				}
				r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{subject}, Options{IgnoreIDs: []string{ignoreID}})
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if markerID == "CVE-2026-1000" || ignoreID == "CVE-2026-1000" || ignoreID == rec.ID {
					want = 0
				}
				if len(r.Findings) != want {
					t.Fatalf("findings=%+v skipped=%v, want %d findings", r.Findings, r.Skipped, want)
				}
				if want == 1 && (r.Findings[0].ID != "CVE-2026-1000" || r.Skipped["distro-not-affected"] != 0) {
					t.Fatalf("source CVE scope lost: %+v", r)
				}
			})
		}
	}
}

func TestR20DoubleVulnerableDistinctCVEs(t *testing.T) {
	for _, samePackage := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			for _, ignored := range []string{"", "CVE-2026-2000"} {
				t.Run(fmt.Sprintf("same-package=%v/reverse=%v/ignore=%s", samePackage, reverse, ignored), func(t *testing.T) {
					rec, subject := r20UbuntuQueries("4.0")
					if samePackage {
						rec.Affected[1].Package = "src"
					}
					if reverse {
						slices.Reverse(rec.Affected)
					}
					r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{subject}, Options{IgnoreIDs: []string{ignored}})
					want := 2
					if ignored != "" {
						want = 1
					}
					if err != nil || len(r.Findings) != want {
						t.Fatalf("distinct CVEs merged: %+v, %v", r, err)
					}
					for i, f := range r.Findings {
						id := rec.Aliases[i]
						if f.ID != id || !slices.Equal(f.Record.Aliases, []string{id}) || !slices.Equal(f.RelatedIDs, unique([]string{rec.ID, id})) {
							t.Fatalf("wrong CVE identity: %+v", f)
						}
					}
				})
			}
		}
	}
}

func TestR20EqualScopeMappedSeverity(t *testing.T) {
	for _, ratings := range [][]string{{"medium", "negligible"}, {"negligible", "medium"}, {"medium", "unimportant"}, {"negligible", "unimportant"}} {
		for _, exclude := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/exclude=%v", ratings, exclude), func(t *testing.T) {
				var records []vulndb.Record
				for i, rating := range ratings {
					rec := advisory("Ubuntu:22.04:LTS", "src", "3.0")
					rec.ID, rec.Aliases = fmt.Sprintf("USN-%d-1", i+1), []string{"CVE-2026-1000"}
					rec.Affected[0].Database = r18CVEMap(rec.Affected[0].Ecosystem, rec.Aliases, rating)
					records = append(records, rec)
				}
				subject := Subject{Ref: "src", Name: "src", Version: "2.0", Type: "deb", Ecosystem: "Ubuntu", Release: "22.04"}
				r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{subject}, Options{ExcludeUnimportant: exclude})
				if err != nil {
					t.Fatal(err)
				}
				allNegligible := !slices.Contains(ratings, "medium")
				if exclude && allNegligible {
					if len(r.Findings) != 0 || r.Skipped["unimportant"] != 2 {
						t.Fatalf("negligible scope retained: %+v", r)
					}
					return
				}
				want := "MEDIUM"
				if allNegligible {
					want = "NEGLIGIBLE"
				}
				if len(r.Findings) != 1 || r.Findings[0].Severity != want || r.Skipped["unimportant"] != 0 {
					t.Fatalf("equal-scope maximum lost: %+v", r)
				}
				if !slices.Contains(r.Findings[0].RelatedIDs, records[0].ID) || !slices.Contains(r.Findings[0].RelatedIDs, records[1].ID) {
					t.Fatalf("rating excluded before merging: %+v", r.Findings[0])
				}
			})
		}
	}
}

func TestR20MappedScopesRetainAdvisoryIDs(t *testing.T) {
	for _, sourceIDs := range [][]string{{}, {"CVE-2026-1000", "CVE-2026-1001"}} {
		t.Run(fmt.Sprint(sourceIDs), func(t *testing.T) {
			rec, subject := r20UbuntuQueries("4.0")
			rec.Affected[0].Database = r18CVEMap(rec.Affected[0].Ecosystem, sourceIDs, "medium")
			binaryIDs := []string{"CVE-2026-2000", "CVE-2026-2001"}
			rec.Affected[1].Database = r18CVEMap(rec.Affected[1].Ecosystem, binaryIDs, "low")
			// Repeated subjects exercise the shared lookup and identity caches.
			subjects := []Subject{subject, subject}
			subjects[1].Ref = "second-bin"
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, subjects, Options{})
			if err != nil || len(r.Findings) != 4 {
				t.Fatalf("advisory scopes merged: %+v, %v", r, err)
			}
			for _, f := range r.Findings {
				ids := sourceIDs
				if f.MatchedBy == "binary-name" {
					ids = binaryIDs
				}
				if f.ID != rec.ID || !slices.Equal(f.Record.Aliases, ids) || !slices.Equal(f.RelatedIDs, unique(append([]string{rec.ID}, ids...))) {
					t.Fatalf("advisory identity leaked: %+v", f)
				}
			}
		})
	}
}
