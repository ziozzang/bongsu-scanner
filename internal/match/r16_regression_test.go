package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestR15CrossStreamNotAffected(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, kind := range []string{"not-affected", "severity", "range"} {
			t.Run(fmt.Sprintf("%s/reverse=%t", kind, reverse), func(t *testing.T) {
				rec := advisory("Red Hat:8", "nodejs", "99-1.el8")
				rec.Affected[0].Database = map[string]any{"modularity": "nodejs:18", "severity": "Low"}
				other := advisory("Red Hat:8", "nodejs", "99-1.el8").Affected[0]
				other.Database = map[string]any{"modularity": "nodejs:20", "severity": "Important"}
				if kind == "not-affected" {
					other.Ranges = nil
					other.Database["redhat_status"] = "not-affected"
				}
				if kind == "range" {
					rec.Affected[0].Ranges = nil
				}
				rec.Affected = append(rec.Affected, other)
				subjects := []Subject{
					{Ref: "18", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Name: "nodejs", Version: "18.0-1.el8", Modularity: "nodejs:18:8060020230301:abcd"},
					{Ref: "20", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Name: "nodejs", Version: "18.0-1.el8", Modularity: "nodejs:20:8060020230301:abcd"},
					{Ref: "other-name", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Name: "nodejs", Version: "18.0-1.el8", Modularity: "other:18:8060020230301:abcd"},
					{Ref: "plain", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Name: "nodejs", Version: "18.0-1.el8"},
				}
				if reverse {
					rec.Affected[0], rec.Affected[1] = rec.Affected[1], rec.Affected[0]
					for i, j := 0, len(subjects)-1; i < j; i, j = i+1, j-1 {
						subjects[i], subjects[j] = subjects[j], subjects[i]
					}
				}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, subjects, Options{SeveritySource: "distro"})
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]string{}
				if kind != "range" {
					want["18"] = "LOW"
				}
				if kind != "not-affected" {
					want["20"] = "HIGH"
				}
				if len(r.Findings) != len(want) || r.Skipped["distro-not-affected"] != 0 {
					t.Fatalf("cross-stream applicability: %+v", r)
				}
				for _, f := range r.Findings {
					if want[f.Subject.Ref] != f.Severity {
						t.Fatalf("stream severity: %+v", f)
					}
				}
			})
		}
	}
}

func TestR15DanglingOwner(t *testing.T) {
	for _, typ := range []string{"rpm", "deb", "apk"} {
		for _, kind := range []string{"absent", "matchable", "ecosystem", "release", "version", "name", "type", "missing-version"} {
			for _, ownerFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/owner-first=%t", typ, kind, ownerFirst), func(t *testing.T) {
					eco := map[string]string{"rpm": "Red Hat", "deb": "Debian", "apk": "Alpine"}[typ]
					os := Subject{Ref: "os", Type: typ, Ecosystem: eco, Release: "8", Name: "python3-idna", Version: "2.5-8"}
					lang := Subject{Ref: "py", Type: "pypi", Ecosystem: "PyPI", Name: "idna", Version: "2.5", Owner: typ + ":python3-idna@2.5-8"}
					records := []vulndb.Record{advisory("PyPI", "idna", "3.7")}
					if kind != "ecosystem" {
						records = append(records, advisory(eco+":8", "unrelated", "99"))
					}
					switch kind {
					case "release":
						os.Release = "9"
					case "version":
						os.Version = "2.5-9"
					case "name":
						os.Name = "other"
					case "type":
						os.Type = "pypi"
					case "missing-version":
						os.Version = ""
						lang.Owner = typ + ":python3-idna@"
					}
					subjects := []Subject{lang}
					if kind != "absent" {
						subjects = append(subjects, os)
						if ownerFirst {
							subjects[0], subjects[1] = subjects[1], subjects[0]
						}
					}
					r, err := Run(context.Background(), &fakeStore{records: records}, subjects, Options{})
					if err != nil {
						t.Fatal(err)
					}
					if kind == "matchable" {
						if len(r.Findings) != 0 || r.Skipped["distro-owned"] != 1 || r.Skipped["owner-unmatched"] != 0 {
							t.Fatalf("matchable owner: %+v", r)
						}
					} else if len(r.Findings) != 1 || r.Findings[0].Subject.Ref != "py" || r.Skipped["owner-unmatched"] != 1 || r.Skipped["distro-owned"] != 0 {
						t.Fatalf("unmatched owner suppressed language subject: %+v", r)
					}
				})
			}
		}
	}
}

func TestR15BinaryImpactPrecedence(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			for _, policy := range []string{"distro", "cvss", "max"} {
				t.Run(fmt.Sprintf("duplicate=%t/reverse=%t/%s", duplicate, reverse, policy), func(t *testing.T) {
					rec := advisory("Red Hat:9", "example-libs", "2-1.el9")
					rec.Database = map[string]any{"severity": "Important"}
					rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
					rec.Affected[0].Database = map[string]any{"severity": "Low"}
					source := advisory("Red Hat:9", "example", "2-1.el9").Affected[0]
					rec.Affected = append(rec.Affected, source)
					records := []vulndb.Record{rec}
					if duplicate {
						fallback := rec
						fallback.Affected = []vulndb.Affected{advisory("Red Hat:9", "example-libs", "2-1.el9").Affected[0], source}
						records = append(records, fallback)
					}
					if reverse {
						rec.Affected[0], rec.Affected[1] = rec.Affected[1], rec.Affected[0]
						if duplicate {
							records[0], records[1] = records[1], records[0]
						}
					}
					subject := Subject{Ref: "r", Type: "rpm", Ecosystem: "Red Hat", Release: "9", Name: "example-libs", Version: "1-1.el9", Upstream: "example", UpstreamVersion: "1-1.el9"}
					r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{subject}, Options{SeveritySource: policy})
					if err != nil || len(r.Findings) != 1 {
						t.Fatalf("report=%+v err=%v", r, err)
					}
					want := "CRITICAL"
					if policy == "distro" {
						want = "LOW"
					}
					f := r.Findings[0]
					if f.Severity != want || f.DistroSeverity != "low" || f.Record.DistroSeverity != "low" || f.Score != 9.8 {
						t.Fatalf("binary impact overridden: %+v", f)
					}
				})
			}
		}
	}
}

func TestR15FixedBinaryEpoch(t *testing.T) {
	for _, upstream := range []string{"", "openssl", "openssl-libs"} {
		t.Run("upstream="+upstream, func(t *testing.T) {
			rec := advisory("Red Hat:9", "openssl-libs", "1:3.0.7-27.el9")
			subject := Subject{Ref: "r", Type: "rpm", Ecosystem: "Red Hat", Release: "9", Name: "openssl-libs", Version: "1:3.0.7-27.el9", Upstream: upstream, UpstreamVersion: "3.0.7-27.el9"}
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{subject}, Options{})
			want := 0
			// A same-name source lookup still uses the explicitly supplied source version.
			if upstream == subject.Name {
				want = 1
			}
			if err != nil || len(r.Findings) != want {
				t.Fatalf("fixed binary matched: %+v err=%v", r, err)
			}
			if want == 1 && r.Findings[0].MatchedBy != "upstream" {
				t.Fatalf("source version not used for upstream lookup: %+v", r.Findings[0])
			}
		})
	}
}
