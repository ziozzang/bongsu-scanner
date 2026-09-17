package match

import (
	"context"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestUbuntuPriorityPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, eco, ubuntu, priority, record, want string
	}{
		{"affected wins", "Ubuntu:24.04:LTS", " Low ", "high", "critical", "low"},
		{"priority fallback", "Ubuntu:24.04:LTS", "", " Medium ", "critical", "medium"},
		{"record wins urgency", "Ubuntu:24.04:LTS", "", "", " Low ", "low"},
		{"pro release", "Ubuntu:Pro:24.04:LTS", "negligible", "", "high", "negligible"},
		{"urgency fallback", "Ubuntu:24.04:LTS", "", "", "", "high"},
		{"other distro", "Debian:13", "low", "low", "low", "high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := vulndb.Record{Severity: []vulndb.Severity{{Type: "Ubuntu", Score: tc.record}}, Database: map[string]any{"urgency": "critical"}}
			a := vulndb.Affected{Ecosystem: tc.eco, Specific: map[string]any{"ubuntu_priority": tc.ubuntu, "priority": tc.priority, "urgency": "medium"}, Database: map[string]any{"urgency": "high"}}
			if got := distroSeverity(rec, a); got != tc.want {
				t.Fatalf("distroSeverity=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestUbuntuPriorityRun(t *testing.T) {
	subject := Subject{Ref: "coreutils", Name: "coreutils", Type: "deb", Ecosystem: "Ubuntu", Release: "24.04", Version: "1.0"}
	for _, priority := range []string{"negligible", "low", "medium", "high", "critical"} {
		for _, mode := range []string{"", "distro", "cvss", "max"} {
			for _, recordLevel := range []bool{false, true} {
				rec := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
				rec.ID, rec.Aliases = "UBUNTU-CVE-2016-2781", []string{"CVE-2016-2781"}
				rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "7.5"}}
				if recordLevel {
					rec.Severity = append(rec.Severity, vulndb.Severity{Type: "Ubuntu", Score: priority})
				} else {
					rec.Affected[0].Specific = map[string]any{"ubuntu_priority": priority, "priority_reason": "limited impact"}
				}
				for _, exclude := range []bool{false, true} {
					r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{subject}, Options{SeveritySource: mode, ExcludeUnimportant: exclude, Details: true})
					if err != nil {
						t.Fatal(err)
					}
					if priority == "negligible" && exclude {
						if len(r.Findings) != 0 || r.Skipped["unimportant"] != 1 {
							t.Fatalf("negligible not excluded: %+v", r)
						}
						continue
					}
					want := normalizeSeverity(priority)
					if mode == "cvss" || mode == "max" && SeverityRank(want) < SeverityRank("HIGH") {
						want = "HIGH"
					}
					if len(r.Findings) != 1 {
						t.Fatalf("findings=%+v", r)
					}
					f := r.Findings[0]
					if f.ID != "CVE-2016-2781" || f.Severity != want || f.DistroSeverity != priority || f.Record.DistroSeverity != priority || f.Score != 7.5 || r.BySeverity[want] != 1 {
						t.Fatalf("%s/%s/record=%v: %+v", priority, mode, recordLevel, r)
					}
					if !recordLevel && f.Affected.Specific["priority_reason"] != "limited impact" {
						t.Fatal("priority_reason lost")
					}
				}
			}
		}
	}
}

func TestUbuntuPriorityAliasDedup(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		vendor := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
		vendor.ID, vendor.Aliases = "UBUNTU-CVE-2016-2781", []string{"CVE-2016-2781"}
		vendor.Affected[0].Specific = map[string]any{"ubuntu_priority": "low"}
		upstream := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
		upstream.ID = "CVE-2016-2781"
		upstream.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "7.5"}}
		records := []vulndb.Record{vendor, upstream}
		if reverse {
			records[0], records[1] = records[1], records[0]
		}
		r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{{Ref: "coreutils", Name: "coreutils", Ecosystem: "Ubuntu", Release: "24.04", Version: "1.0"}}, Options{})
		if err != nil || len(r.Findings) != 1 {
			t.Fatalf("%+v %v", r, err)
		}
		f := r.Findings[0]
		if f.ID != "CVE-2016-2781" || f.Severity != "LOW" || f.DistroSeverity != "low" || f.Score != 7.5 {
			t.Fatalf("merged: %+v", f)
		}
	}
}

func TestUbuntuNegligibleRangeMissDoesNotSuppressHit(t *testing.T) {
	for _, fixed := range []string{"0.5", ""} {
		positive := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
		positive.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "7.5"}}
		marker := advisory("Ubuntu:24.04:LTS", "coreutils", fixed)
		marker.ID, marker.Aliases = "UBUNTU-CVE-2026-1234", []string{positive.ID}
		marker.Affected[0].Specific = map[string]any{"ubuntu_priority": "negligible"}
		if fixed == "" {
			marker.Affected[0].Ranges = nil
		}
		r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{marker, positive}}, []Subject{{Ref: "coreutils", Name: "coreutils", Ecosystem: "Ubuntu", Release: "24.04", Version: "1.0"}}, Options{ExcludeUnimportant: true})
		if err != nil || len(r.Findings) != 1 || r.Findings[0].Severity != "HIGH" || r.Findings[0].DistroSeverity != "" {
			t.Fatalf("marker suppressed hit: %+v %v", r, err)
		}
	}
}

func TestUbuntuNegligibleAliasExclusion(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		vendor := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
		vendor.ID, vendor.Aliases = "UBUNTU-CVE-2016-2781", []string{"CVE-2016-2781"}
		vendor.Affected[0].Specific = map[string]any{"ubuntu_priority": "negligible"}
		upstream := advisory("Ubuntu:24.04:LTS", "coreutils", "2.0")
		upstream.ID = "CVE-2016-2781"
		upstream.Affected[0].Database = map[string]any{"urgency": "high"}
		records := []vulndb.Record{vendor, upstream}
		if reverse {
			records[0], records[1] = records[1], records[0]
		}
		for _, exclude := range []bool{false, true} {
			r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{{Ref: "coreutils", Name: "coreutils", Ecosystem: "Ubuntu", Release: "24.04", Version: "1.0"}}, Options{ExcludeUnimportant: exclude})
			if err != nil {
				t.Fatal(err)
			}
			if exclude {
				if len(r.Findings) != 0 || r.Skipped["unimportant"] != 2 {
					t.Errorf("positive negligible alias not excluded: %+v", r)
				}
			} else if len(r.Findings) != 1 || r.Findings[0].Severity != "NEGLIGIBLE" || r.Findings[0].DistroSeverity != "negligible" {
				t.Errorf("negligible priority lost across aliases: %+v", r)
			}
		}
	}
}
