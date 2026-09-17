package match

import (
	"context"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func (s *fakeStore) LookupCPE(vendor, product string) ([]vulndb.Record, error) { return s.records, nil }
func (*benchmarkStore) LookupCPE(string, string) ([]vulndb.Record, error)      { return nil, nil }
func (*largePackageStore) LookupCPE(string, string) ([]vulndb.Record, error)   { return nil, nil }

func TestCPEInventoryLoad(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"python","name":"python","version":"3.12.4","purl":"pkg:generic/python@3.12.4","cpe":"cpe:2.3:a:python:python:3.12.4:*:*:*:*:*:*:*"},{"bom-ref":"os","type":"operating-system","name":"debian","version":"13","cpe":"cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:*"}]}`)
	d, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Subjects) != 2 {
		t.Fatalf("subjects: %+v", d.Subjects)
	}
	path := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	streamed, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.Subjects, streamed.Subjects) {
		t.Fatal("stream CPE inventory differs")
	}
}

func TestCPEMatchingConservative(t *testing.T) {
	for _, tt := range []struct {
		name, version string
		mutate        func(*vulndb.Affected, *Subject)
		want          int
		confidence    string
	}{
		{name: "python vulnerable", version: "3.12.4", want: 1, confidence: "low"},
		{name: "exclusive end", version: "3.12.5"},
		{name: "semver prerelease", version: "3.12.5-rc.1", want: 1, confidence: "low"},
		{name: "exclusive start", version: "3.12.0", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["versionStartExcluding"] = "3.12.0" }},
		{name: "AND", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["requires_and"] = true }},
		{name: "negated", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["negate"] = true }},
		{name: "children", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["node_children"] = true }},
		{name: "wildcard product", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["cpe"] = "cpe:2.3:a:python:*:*:*:*:*:*:*:*:*" }},
		{name: "different vendor", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["cpe"] = "cpe:2.3:a:other:python:*:*:*:*:*:*:*:*" }},
		{name: "wrong target software", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) {
			a.Database["cpe"] = "cpe:2.3:a:python:python:*:*:*:*:*:windows:*:*"
		}},
		{name: "matching target software", version: "3.12.4", want: 1, confidence: "low", mutate: func(a *vulndb.Affected, s *Subject) {
			a.Database["cpe"] = "cpe:2.3:a:python:python:*:*:*:*:*:pypi:*:*"
			s.Ecosystem = "PyPI"
		}},
		{name: "unknown hardware", version: "3.12.4", mutate: func(a *vulndb.Affected, _ *Subject) { a.Database["cpe"] = "cpe:2.3:a:python:python:*:*:*:*:*:*:x64:*" }},
		{name: "exact criteria", version: "3.12.4", want: 1, confidence: "high", mutate: func(a *vulndb.Affected, _ *Subject) {
			a.Database["cpe"] = "cpe:2.3:a:python:python:3.12.4:*:*:*:*:*:*:*"
			a.Ranges = nil
			a.Versions = []string{"3.12.4"}
		}},
		{name: "inclusive end", version: "3.12.5", want: 1, confidence: "low", mutate: func(a *vulndb.Affected, _ *Subject) { a.Ranges[0].Events[1] = vulndb.Event{LastAffected: "3.12.5"} }},
		{name: "unknown version", version: "*"},
		{name: "inconsistent inventory", version: "3.12.4", mutate: func(_ *vulndb.Affected, s *Subject) { s.CPE = "cpe:2.3:a:python:python:3.12.5" }},
		{name: "debian OS", version: "13", want: 1, confidence: "high", mutate: func(a *vulndb.Affected, s *Subject) {
			s.CPE = "cpe:2.3:o:debian:debian_linux:13"
			a.Package = "debian:debian_linux"
			a.Database["cpe"] = s.CPE
			a.Ranges = nil
			a.Versions = []string{"13"}
		}},
		{name: "generic alias", version: "3.12.4", want: 1, confidence: "low", mutate: func(_ *vulndb.Affected, s *Subject) {
			s.CPE = ""
			s.PURL = purl.PURL{Type: "generic", Name: "python", Version: s.Version}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := advisory("CPE", "python:python", "3.12.5")
			r.Affected[0].Database = map[string]any{"cpe": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", "operator": "OR"}
			s := Subject{Ref: "python", Name: "python", Version: tt.version, CPE: "cpe:2.3:a:python:python:" + tt.version}
			if tt.mutate != nil {
				tt.mutate(&r.Affected[0], &s)
			}
			for _, enabled := range []bool{false, true} {
				report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{s}, Options{CPE: enabled})
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if enabled {
					want = tt.want
				}
				if len(report.Findings) != want {
					t.Fatalf("enabled=%v got=%+v want=%d", enabled, report.Findings, want)
				}
				if want > 0 && (report.Findings[0].Confidence != tt.confidence || report.Findings[0].MatchedBy != "cpe") {
					t.Fatalf("finding: %+v", report.Findings[0])
				}
			}
		})
	}
}

func TestCPEDedupeAndFilters(t *testing.T) {
	r := advisory("CPE", "python:python", "3.12.5")
	r.Affected[0].Database = map[string]any{"cpe": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", "operator": "OR"}
	osv := advisory("PyPI", "python", "3.12.5")
	osv.ID = "GHSA-fixture"
	osv.Aliases = []string{r.ID}
	s := Subject{Ref: "python", Name: "python", Version: "3.12.4", Ecosystem: "PyPI", CPE: "cpe:2.3:a:python:python:3.12.4"}
	report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r, osv}}, []Subject{s}, Options{CPE: true})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].MatchedBy == "cpe" {
		t.Fatalf("dedupe: %+v %v", report, err)
	}
	for _, opts := range []Options{{CPE: true, IgnoreIDs: []string{r.ID}}, {CPE: true, MinSeverity: "CRITICAL"}} {
		report, err = Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{s}, opts)
		if err != nil || len(report.Findings) != 0 {
			t.Fatalf("filter: %+v %v", report, err)
		}
	}
	s.Ref = "other"
	report, err = Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{s, {Ref: "second", Version: "3.12.4", CPE: s.CPE}}, Options{CPE: true, OnlyFixed: true})
	if err != nil || len(report.Findings) != 2 {
		t.Fatalf("per-subject CPE: %+v %v", report, err)
	}
}
