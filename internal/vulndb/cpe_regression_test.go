package vulndb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const cpeNVD = `{"vulnerabilities":[{"cve":{"id":"CVE-2025-4321","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:python:python:*:*:*:*:*:*:*:*","versionStartExcluding":"3.12.0","versionEndExcluding":"3.12.5"},{"vulnerable":false,"criteria":"cpe:2.3:a:other:product:1:*:*:*:*:*:*:*"},{"vulnerable":true,"criteria":"cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:*"}]}]},{"operator":"AND","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:python:python:3.12.4:*:*:*:*:*:*:*"}]}]}]}}]}`

func TestNVDCPEIngestionAndSQLiteLookup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.gz")
	if err := os.WriteFile(path, nvdGzip(t, cpeNVD), 0600); err != nil {
		t.Fatal(err)
	}
	var records []*Record
	feeds, err := (nvdSource{NVDOptions{Years: "2025"}}).Feeds(&Options{})
	if err != nil {
		t.Fatal(err)
	}
	var progress []string
	err = feeds[0].Parse(context.Background(), path, 0, func(r *Record) error { records = append(records, r); return nil }, func(s string) { progress = append(progress, s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].Affected) != 3 {
		t.Fatalf("records: %+v", records)
	}
	a := records[0].Affected
	if a[0].Ecosystem != "CPE" || a[0].Package != "python:python" || len(a[0].Ranges) != 1 || a[0].Ranges[0].Events[1].Fixed != "3.12.5" {
		t.Fatalf("range: %+v", a[0])
	}
	if len(a[1].Versions) != 1 || a[1].Versions[0] != "13" || a[2].Database["requires_and"] != true {
		t.Fatalf("entries: %+v", a)
	}
	if !strings.Contains(strings.Join(progress, "\n"), "1") {
		t.Fatalf("missing AND count: %v", progress)
	}
	meta := Meta{}
	if err := buildSQLite(context.Background(), dir, map[string]*Record{records[0].ID: records[0]}, &meta); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	lookup, ok := st.(interface {
		LookupCPE(string, string) ([]Record, error)
	})
	if !ok {
		t.Fatal("missing LookupCPE")
	}
	got, err := lookup.LookupCPE("python", "python")
	if err != nil || len(got) != 1 {
		t.Fatalf("lookup: %v %v", got, err)
	}
	sort.Slice(records[0].Affected, func(i, j int) bool {
		x, _ := json.Marshal(records[0].Affected[i])
		y, _ := json.Marshal(records[0].Affected[j])
		return string(x) < string(y)
	})
	sort.Slice(got[0].Affected, func(i, j int) bool {
		x, _ := json.Marshal(got[0].Affected[i])
		y, _ := json.Marshal(got[0].Affected[j])
		return string(x) < string(y)
	})
	want, _ := json.Marshal(records[0].Affected)
	actual, _ := json.Marshal(got[0].Affected)
	if string(want) != string(actual) {
		t.Fatalf("CPE metadata lost: %s", actual)
	}
	got, err = lookup.LookupCPE("other", "python")
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-vendor lookup: %v %v", got, err)
	}
}

func (noIDStore) LookupCPE(string, string) ([]Record, error) { return nil, nil }

func TestNVDCPEBooleanTreeAndBounds(t *testing.T) {
	criteria := "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"
	match := nvdCPEMatch{Vulnerable: true, Criteria: criteria, StartIncluding: "3.12.0", EndIncluding: "3.12.5"}
	for _, tt := range []struct {
		name        string
		node        nvdNode
		and, negate bool
	}{
		{name: "OR", node: nvdNode{Operator: "OR", Matches: []nvdCPEMatch{match}}},
		{name: "AND node", node: nvdNode{Operator: "AND", Matches: []nvdCPEMatch{match}}, and: true},
		{name: "nested AND", node: nvdNode{Operator: "AND", Children: []nvdNode{{Operator: "OR", Matches: []nvdCPEMatch{match}}}}, and: true},
		{name: "negated ancestor", node: nvdNode{Operator: "OR", Negate: true, Children: []nvdNode{{Operator: "OR", Matches: []nvdCPEMatch{match}}}}, negate: true},
		{name: "unknown operator", node: nvdNode{Operator: "XOR", Children: []nvdNode{{Operator: "OR", Matches: []nvdCPEMatch{match}}}}, and: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := convertNVD(nvdCVE{Configurations: []nvdNode{{Nodes: []nvdNode{tt.node}}}})
			if len(r.Affected) != 1 {
				t.Fatalf("affected: %+v", r.Affected)
			}
			a := r.Affected[0]
			if (a.Database["requires_and"] == true) != tt.and || (a.Database["negate"] == true) != tt.negate {
				t.Fatalf("boolean semantics: %+v", a.Database)
			}
			if len(a.Ranges) != 1 || a.Ranges[0].Events[0].Introduced != "3.12.0" || a.Ranges[0].Events[1].LastAffected != "3.12.5" {
				t.Fatalf("bounds: %+v", a.Ranges)
			}
		})
	}
}

func TestCPEAttributesEscapes(t *testing.T) {
	parts, ok := CPEAttributes(`cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*`)
	if !ok || parts[2] != `product\:name` || len(parts) != 11 {
		t.Fatalf("escaped colon: %v %v", parts, ok)
	}
	for _, raw := range []string{"cpe:/a:python:python:3", "cpe:2.3:a:python", "cpe:2.3:a:python::1", "cpe:2.3:a:python:python:1\\", "cpe:2.3:x:python:python:1"} {
		if _, ok := CPEAttributes(raw); ok {
			t.Fatalf("accepted malformed CPE %q", raw)
		}
	}
}
