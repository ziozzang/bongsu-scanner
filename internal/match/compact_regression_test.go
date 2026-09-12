package match

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestFindingSummaryIsBounded(t *testing.T) {
	rec := advisory("PyPI", "fixture", "2.0")
	rec.Summary = strings.Repeat("한", 501)
	rec.Details = "full details must be opt-in"
	rec.Affected[0].Versions = []string{"1.0"}
	for i := 0; i < 8; i++ {
		rec.References = append(rec.References, vulndb.Reference{Type: "WEB", URL: "https://example.org/advisory"})
	}
	report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{{Ref: "ref", Name: "fixture", Ecosystem: "PyPI", Version: "1.0"}}, Options{})
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, "json", report, Document{}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Record   map[string]any
			Affected map[string]any
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	r := got.Findings[0].Record
	if utf8.RuneCountInString(r["summary"].(string)) != 500 {
		t.Error("summary must contain at most 500 characters")
	}
	for _, key := range []string{"details", "affected", "database_specific", "related", "provenance"} {
		if _, ok := r[key]; ok {
			t.Errorf("unexpected full record field %s", key)
		}
	}
	if refs, ok := r["references"].([]any); !ok || len(refs) != 5 {
		t.Errorf("references=%v", r["references"])
	}
	if _, ok := got.Findings[0].Affected["versions"]; ok {
		t.Error("matched affected must omit explicit versions")
	}
	if len(rec.Affected[0].Versions) != 1 || len(rec.References) != 8 {
		t.Error("store record was mutated")
	}
}

func TestRepeatedExplicitVersionsAllocationBudget(t *testing.T) {
	rec := advisory("PyPI", "fixture", "2.0")
	rec.Affected[0].Versions = make([]string, 1000)
	for i := range rec.Affected[0].Versions {
		rec.Affected[0].Versions[i] = "1.0.0"
	}
	store := &fakeStore{records: []vulndb.Record{rec}}
	subjects := make([]Subject, 20)
	for i := range subjects {
		subjects[i] = Subject{Ref: "ref", Name: "fixture", Ecosystem: "PyPI", Version: "1.0"}
	}
	allocs := testing.AllocsPerRun(1, func() {
		report, err := Run(context.Background(), store, subjects, Options{})
		if err != nil || len(report.Findings) != 1 {
			t.Fatalf("findings=%d err=%v", len(report.Findings), err)
		}
	})
	if allocs > 10000 {
		t.Fatalf("repeated versions allocated %.0f objects; want <=10000", allocs)
	}
}

func TestDetailsAndAssessmentRetainFullText(t *testing.T) {
	rec := advisory("PyPI", "fixture", "2.0")
	rec.Summary = strings.Repeat("한", 600)
	rec.Details = strings.Repeat("full advisory text ", 1000)
	rec.DetailsTruncated = true
	for i := 0; i < 8; i++ {
		rec.References = append(rec.References, vulndb.Reference{URL: fmt.Sprintf("https://example.org/%d", i)})
	}
	subject := Subject{Ref: "ref", Name: "fixture", Ecosystem: "PyPI", Version: "1.0"}
	for _, details := range []bool{false, true} {
		report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{subject}, Options{Details: details})
		if err != nil {
			t.Fatal(err)
		}
		f := report.Findings[0]
		if details && (f.Record.Details != rec.Details || !f.Record.DetailsTruncated) {
			t.Fatal("full details or truncation marker lost")
		}
		if !details && f.Record.Details != "" {
			t.Fatal("details must be opt-in")
		}
		called := false
		analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
			called = true
			if in.Summary != rec.Summary || in.Description != rec.Details || !in.DescriptionTruncated || len(in.References) != 8 {
				t.Fatalf("assessment text changed: %+v", in)
			}
			return assessment.Result{Status: "needs_review"}, nil
		})
		if err := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("assessment was not invoked")
		}
	}
}

type chunkBoundedWriter struct {
	max int
	bytes.Buffer
}

func (w *chunkBoundedWriter) Write(data []byte) (int, error) {
	if len(data) > w.max {
		return 0, fmt.Errorf("report-sized write: %d bytes", len(data))
	}
	return w.Buffer.Write(data)
}
func TestJSONWritesBoundedFindingChunks(t *testing.T) {
	report := Report{Subjects: 1000, Findings: make([]Finding, 1000), Skipped: map[string]int{"missing-version": 1}, BySeverity: map[string]int{"HIGH": 1000}}
	for i := range report.Findings {
		report.Findings[i] = Finding{ID: fmt.Sprint(i), Subject: Subject{Ref: fmt.Sprint(i)}, Record: RecordSummary{Summary: strings.Repeat("x", 500)}}
	}
	out := &chunkBoundedWriter{max: 4096}
	if err := Write(out, "json", report, Document{}); err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("streaming changed the JSON fields")
	}
}

func TestPreparedVersionsAndReleasesStayIsolated(t *testing.T) {
	records := []vulndb.Record{advisory("Debian:12", "fixture", "2"), advisory("Debian:13", "fixture", "4")}
	records[1].ID = "CVE-2026-5678"
	subjects := []Subject{
		{Ref: "old", Name: "fixture", Ecosystem: "Debian", Release: "12", Version: "3"},
		{Ref: "new", Name: "fixture", Ecosystem: "Debian", Release: "13", Version: "3"},
		{Ref: "fixed", Name: "fixture", Ecosystem: "Debian", Release: "13", Version: "4"},
	}
	report, err := Run(context.Background(), &fakeStore{records: records}, subjects, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Subject.Ref != "new" || report.Findings[0].ID != "CVE-2026-5678" {
		t.Fatalf("cache leaked version/release: %+v", report.Findings)
	}
}

func TestJSONPreservesNilAndEmptyFindings(t *testing.T) {
	for _, findings := range [][]Finding{nil, {}} {
		var out bytes.Buffer
		if err := Write(&out, "json", Report{Findings: findings}, Document{}); err != nil {
			t.Fatal(err)
		}
		var got struct{ Findings []Finding }
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if (got.Findings == nil) != (findings == nil) {
			t.Fatal("nil and empty findings changed")
		}
	}
}
