package match

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"os"
	"strings"
	"testing"
)

type fakeStore struct {
	records []vulndb.Record
	calls   int
}

func (s *fakeStore) Lookup(eco, name string) ([]vulndb.Record, error) {
	s.calls++
	return s.records, nil
}
func (s *fakeStore) Ecosystems() ([]string, error) {
	var ecosystems []string
	for _, r := range s.records {
		for _, a := range r.Affected {
			ecosystems = append(ecosystems, a.Ecosystem)
		}
	}
	return unique(ecosystems), nil
}
func (s *fakeStore) Meta() (vulndb.Meta, error) { return vulndb.Meta{Records: len(s.records)}, nil }
func (s *fakeStore) Close() error               { return nil }
func advisory(eco, name, fixed string) vulndb.Record {
	return vulndb.Record{ID: "CVE-2026-1234", Affected: []vulndb.Affected{{Ecosystem: eco, Package: name, Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}
}
func TestRunEcosystems(t *testing.T) {
	tests := []struct {
		name, eco, release, typ, pkg, ver, affectedEco, fixed, upstream, upver string
		want                                                                   int
	}{
		{name: "debian vulnerable", eco: "Debian", release: "13", typ: "deb", pkg: "curl", ver: "8.14.1-2+deb13u3", affectedEco: "Debian:13", fixed: "8.14.1-2+deb13u4", want: 1},
		{name: "debian patched", eco: "Debian", release: "13", typ: "deb", pkg: "curl", ver: "8.14.1-2+deb13u3", affectedEco: "Debian:13", fixed: "8.14.1-2+deb13u2"},
		{name: "wrong release", eco: "Debian", release: "13", typ: "deb", pkg: "curl", ver: "8.14.1-2+deb13u3", affectedEco: "Debian:12", fixed: "99"},
		{name: "unknown release", eco: "Debian", typ: "deb", pkg: "curl", ver: "1", affectedEco: "Debian:13", fixed: "99"},
		{name: "upstream", eco: "Debian", release: "13", typ: "deb", pkg: "libexpat1", ver: "2.6.0-1", affectedEco: "Debian:13", fixed: "2.7.0-1", upstream: "expat", want: 1},
		{name: "upstream version", eco: "Debian", release: "13", typ: "deb", pkg: "libexpat1", ver: "99", affectedEco: "Debian:13", fixed: "2.7.0-1", upstream: "expat", upver: "2.6.0-1", want: 1},
		{name: "alpine", eco: "Alpine", release: "v3.20", typ: "apk", pkg: "openssl", ver: "3.3.0-r0", affectedEco: "Alpine:v3.20", fixed: "3.3.0-r1", want: 1},
		{name: "scoped npm", eco: "npm", typ: "npm", pkg: "@scope/foo", ver: "1.2.3", affectedEco: "npm", fixed: "1.2.4", want: 1},
		{name: "pypi normalized", eco: "PyPI", typ: "pypi", pkg: "PyYAML", ver: "5.1", affectedEco: "PyPI", fixed: "6.0", want: 1},
		{name: "go pseudo", eco: "Go", typ: "golang", pkg: "example.com/foo", ver: "v0.0.0-20230101000000-abcdefabcdef", affectedEco: "Go", fixed: "v0.0.0-20240101000000-abcdefabcdef", want: 1},
		{name: "stdlib", eco: "Go", typ: "golang", pkg: "stdlib", ver: "1.23.0", affectedEco: "Go", fixed: "1.23.1", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := tt.pkg
			if tt.upstream != "" {
				name = tt.upstream
			}
			rec := advisory(tt.affectedEco, strings.ToLower(name), tt.fixed)
			s := Subject{Ref: "x", Name: tt.pkg, Version: tt.ver, Ecosystem: tt.eco, Release: tt.release, Type: tt.typ, Upstream: tt.upstream, UpstreamVersion: tt.upver}
			r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{s}, Options{})
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Findings) != tt.want {
				t.Fatalf("findings=%+v, skips=%v", r.Findings, r.Skipped)
			}
			if tt.want > 0 && tt.upstream != "" && r.Findings[0].MatchedBy != "upstream" {
				t.Fatal("lost upstream priority")
			}
		})
	}
}
func TestRanges(t *testing.T) {
	tests := []struct {
		name, version string
		events        []vulndb.Event
		want          bool
	}{
		{"introduced inclusive", "1.0", []vulndb.Event{{Introduced: "1.0"}, {Fixed: "2.0"}}, true},
		{"fixed exclusive", "2.0", []vulndb.Event{{Introduced: "1.0"}, {Fixed: "2.0"}}, false},
		{"last affected inclusive", "2.0", []vulndb.Event{{Introduced: "1.0"}, {LastAffected: "2.0"}}, true},
		{"last affected after", "2.0.1", []vulndb.Event{{Introduced: "1.0"}, {LastAffected: "2.0"}}, false},
		{"limit exclusive", "2.0", []vulndb.Event{{Introduced: "0"}, {Limit: "2.0"}}, false},
		{"limit inside", "1.9", []vulndb.Event{{Introduced: "0"}, {Limit: "2.0"}}, true},
		{"gap", "2.5", []vulndb.Event{{Introduced: "1.0"}, {Fixed: "2.0"}, {Introduced: "3.0"}, {Fixed: "4.0"}}, false},
		{"second interval", "3.5", []vulndb.Event{{Introduced: "1.0"}, {Fixed: "2.0"}, {Introduced: "3.0"}, {Fixed: "4.0"}}, true},
		{"unbounded", "99.0", []vulndb.Event{{Introduced: "1.0"}}, true},
		{"unknown version order", "release-snapshot", []vulndb.Event{{Introduced: "0"}, {Fixed: "2.0"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, _, _, _ := affectedVersion("npm", tt.version, vulndb.Affected{Ranges: []vulndb.Range{{Type: "SEMVER", Events: tt.events}}})
			if hit != tt.want {
				t.Fatalf("hit=%t", hit)
			}
		})
	}
	for _, a := range []vulndb.Affected{{}, {Ranges: []vulndb.Range{{Type: "GIT", Events: []vulndb.Event{{Introduced: "0"}}}}}} {
		hit, _, _, reason := affectedVersion("npm", "1.0", a)
		if hit || reason == "" {
			t.Fatal("missing/GIT range should skip")
		}
	}
	hit, _, _, _ := affectedVersion("PyPI", "1.0.0", vulndb.Affected{Versions: []string{"1.0"}})
	if !hit {
		t.Fatal("normalized exact version missed")
	}
	hit, _, low, _ := affectedVersion("unsupported", "snapshot", vulndb.Affected{Versions: []string{"snapshot"}})
	if !hit || !low {
		t.Fatal("exact unknown version should be low confidence")
	}
}
func TestRunFiltersAndAliases(t *testing.T) {
	s := Subject{Ref: "x", Name: "foo", Version: "1.0", Ecosystem: "npm", Type: "npm"}
	rec := advisory("npm", "foo", "2.0")
	rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	ghsa := rec
	ghsa.ID = "GHSA-abcd"
	ghsa.Aliases = []string{rec.ID}
	store := &fakeStore{records: []vulndb.Record{ghsa, rec}}
	r, e := Run(context.Background(), store, []Subject{s}, Options{})
	if e != nil || len(r.Findings) != 1 || r.Findings[0].ID != rec.ID || len(r.Findings[0].RelatedIDs) != 2 {
		t.Fatalf("alias merge: %+v %v", r, e)
	}
	if !ShouldFail(r, "high") || ShouldFail(r, "") {
		t.Fatal("fail threshold")
	}
	for _, opts := range []Options{{IgnoreIDs: []string{rec.ID}}, {MinSeverity: "CRITICAL", IgnoreIDs: []string{rec.ID}}} {
		r, e := Run(context.Background(), store, []Subject{s}, opts)
		if e != nil || len(r.Findings) != 0 {
			t.Fatalf("filter: %+v %v", r, e)
		}
	}
	withdrawn := rec
	withdrawn.Withdrawn = "2026-01-01T00:00:00Z"
	r, _ = Run(context.Background(), &fakeStore{records: []vulndb.Record{withdrawn}}, []Subject{s}, Options{})
	if len(r.Findings) > 0 {
		t.Fatal("withdrawn matched")
	}
	rec.Affected[0].Database = map[string]any{"urgency": "unimportant"}
	for _, exclude := range []bool{false, true} {
		r, _ = Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{s}, Options{ExcludeUnimportant: exclude})
		if (len(r.Findings) > 0) == exclude {
			t.Fatal("unimportant option")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Run(ctx, store, []Subject{s}, Options{}); e == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestUpstreamVersionWithoutBinaryVersion(t *testing.T) {
	rec := advisory("Debian:13", "expat", "2.7.0-1")
	s := Subject{Ref: "x", Name: "libexpat1", Ecosystem: "Debian", Release: "13", Type: "deb", Upstream: "expat", UpstreamVersion: "2.6.0-1"}
	r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{s}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].MatchedBy != "upstream" {
		t.Fatalf("upstream-only subject was skipped: findings=%+v skips=%v", r.Findings, r.Skipped)
	}
}

func TestDistinctMultiCVEAdvisoriesDoNotMerge(t *testing.T) {
	first := advisory("npm", "lodash", "2.0.0")
	first.ID = "GHSA-first"
	first.Summary = "first advisory"
	first.Details = "first details"
	first.Aliases = []string{"CVE-2024-1000", "CVE-2025-1000"}
	second := advisory("npm", "lodash", "3.0.0")
	second.ID = "GHSA-second"
	second.Summary = "second advisory"
	second.Details = "second details"
	second.Aliases = []string{"CVE-2024-1000", "CVE-2025-1000"}
	s := Subject{Ref: "x", Name: "lodash", Version: "1.0.0", Ecosystem: "npm", Type: "npm"}
	r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{first, second}}, []Subject{s}, Options{Details: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("multi-CVE records merged: %+v", r.Findings)
	}
	got := map[string]Finding{}
	for _, f := range r.Findings {
		got[f.ID] = f
	}
	for id, want := range map[string]struct {
		details string
		fixed   string
	}{"GHSA-first": {details: "first details", fixed: "2.0.0"}, "GHSA-second": {details: "second details", fixed: "3.0.0"}} {
		f, ok := got[id]
		if !ok || f.Record.Details != want.details || len(f.FixedIn) != 1 || f.FixedIn[0] != want.fixed {
			t.Fatalf("record %s was merged or replaced: %+v", id, f)
		}
	}
}
func TestLoadAndOutput(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"operating-system","name":"alpine","version":"3.20.10"},{"type":"library","bom-ref":"keep-me","name":"openssl","version":"3.3.0-r0","purl":"pkg:apk/alpine/openssl@3.3.0-r0?upstream=openssl%403.3.0-r0"},{"bom-ref":"no-purl","name":"unknown","version":"1"}]}`)
	d, e := Load(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.Subjects) != 2 || d.Subjects[0].Release != "v3.20" || d.Subjects[0].UpstreamVersion != "3.3.0-r0" {
		t.Fatalf("document: %+v", d)
	}
	r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Alpine:v3.20", "openssl", "3.3.0-r1")}}, d.Subjects, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Skipped["unknown-ecosystem"] != 1 {
		t.Fatal("missing purl not counted")
	}
	for _, format := range []string{"table", "json", "cyclonedx"} {
		var b bytes.Buffer
		if e := Write(&b, format, r, d); e != nil {
			t.Fatal(e)
		}
		if format == "table" {
			if !strings.Contains(b.String(), "CVE-2026-1234") {
				t.Fatal("missing table finding")
			}
			continue
		}
		var m map[string]any
		if e := json.Unmarshal(b.Bytes(), &m); e != nil {
			t.Fatal(e)
		}
		if format == "cyclonedx" {
			v := obj(arr(m["vulnerabilities"])[0])
			if str(obj(arr(v["affects"])[0]), "ref") != "keep-me" {
				t.Fatal("bom ref changed")
			}
		}
	}
	if _, ok := d.Raw["vulnerabilities"]; ok {
		t.Fatal("output mutated input")
	}
	if e := Write(&bytes.Buffer{}, "invalid", r, d); e == nil {
		t.Fatal("invalid output accepted")
	}
	spdx := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-OS","name":"debian","versionInfo":"13","primaryPackagePurpose":"OPERATING-SYSTEM"},{"SPDXID":"SPDXRef-A","name":"foo","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/foo@1?distro=debian-12"}]}]}`)
	sd, e := Load(spdx)
	if e != nil || len(sd.Subjects) != 1 || sd.Subjects[0].Release != "12" {
		t.Fatalf("SPDX load %+v %v", sd, e)
	}
	var b bytes.Buffer
	if e := Write(&b, "cyclonedx", r, sd); e != nil {
		t.Fatal(e)
	}
}
func TestExistingHostSBOMs(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture or external integration; run without -short")
	}
	for _, name := range []string{"../../host.cdx.json", "../../host.spdx.json"} {
		t.Run(name, func(t *testing.T) {
			if _, e := os.Stat(name); os.IsNotExist(e) {
				t.Skip("host fixture absent")
			}
			d, e := LoadFile(name)
			if e != nil {
				t.Fatal(e)
			}
			if len(d.Subjects) < 1 {
				t.Fatal("no subjects")
			}
			counts := map[string]int{}
			for _, s := range d.Subjects {
				counts[s.Ecosystem]++
			}
			t.Logf("%d subjects: %v", len(d.Subjects), counts)
		})
	}
}

func TestCoverageGaps(t *testing.T) {
	store := &fakeStore{records: []vulndb.Record{advisory("Alpine:v3.20", "musl", "2.0")}}
	subjects := []Subject{{Ref: "1", Name: "musl", Version: "1.0", Ecosystem: "Alpine", Release: "v3.19"}, {Ref: "2", Name: "curl", Version: "1.0", Ecosystem: "Debian", Release: "13"}}
	r, e := Run(context.Background(), store, subjects, Options{})
	if e != nil || r.Skipped["ecosystem-not-in-database"] != 1 || r.Skipped["release-not-in-database"] != 1 {
		t.Fatalf("coverage %+v %v", r, e)
	}
}
func TestMalformedOpenRangeSkipped(t *testing.T) {
	hit, _, _, reason := affectedVersion("npm", "unknown", vulndb.Affected{Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}}}}})
	if hit || reason == "" {
		t.Fatal("unparseable version matched open range")
	}
}
func TestMergeSeverityDoesNotDowngrade(t *testing.T) {
	dst := Finding{Severity: "HIGH", Score: 0}
	mergeFinding(&dst, Finding{Severity: "MEDIUM", Score: 6})
	if dst.Severity != "HIGH" {
		t.Fatal("severity downgraded")
	}
}
func TestTableSanitizesExternalText(t *testing.T) {
	r := Report{Findings: []Finding{{Subject: Subject{Name: "evil\x1b[2Jname\nrow", Version: "1\t2"}, ID: "CVE\x00evil"}}}
	var b bytes.Buffer
	if e := Write(&b, "table", r, Document{}); e != nil {
		t.Fatal(e)
	}
	if strings.ContainsAny(b.String(), "\x1b\x00") || strings.Contains(b.String(), "name\nrow") {
		t.Fatalf("untrusted control output %q", b.String())
	}
}
func TestLegacySPDXOSMetadata(t *testing.T) {
	d, e := Load([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Root","name":"host","packageComment":"bscan host metadata: {\"operating_system\":\"debian\",\"os_version\":\"13\"}"},{"SPDXID":"SPDXRef-A","name":"curl","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/curl@1"}]}]}`))
	if e != nil || d.Subjects[1].Release != "13" {
		t.Fatalf("legacy SPDX OS %+v %v", d, e)
	}
}
func TestReleaseNormalization(t *testing.T) {
	for _, tt := range []struct{ eco, distro, want string }{{"Debian", "debian-13", "13"}, {"Debian", "debian-bookworm", "12"}, {"Ubuntu", "ubuntu-24.04", "24.04"}, {"Alpine", "alpine-3.20.10", "v3.20"}, {"Wolfi", "wolfi", ""}} {
		if got := release(tt.eco, tt.distro); got != tt.want {
			t.Fatalf("release %s: %s", tt.distro, got)
		}
	}
}

func TestUnsortedEvents(t *testing.T) {
	a := vulndb.Affected{Ranges: []vulndb.Range{{Type: "SEMVER", Events: []vulndb.Event{{Fixed: "4.0"}, {Introduced: "3.0"}, {Fixed: "2.0"}, {Introduced: "1.0"}}}}}
	hit, fixed, _, _ := affectedVersion("npm", "3.5", a)
	if !hit || len(fixed) != 1 || fixed[0] != "4.0" {
		t.Fatalf("unsorted events %t %v", hit, fixed)
	}
	hit, _, _, _ = affectedVersion("npm", "2.5", a)
	if hit {
		t.Fatal("gap became affected after sorting")
	}
}
func TestPURLOnlyAffectedAndLookupCache(t *testing.T) {
	rec := advisory("npm", "", "2.0")
	rec.Affected[0].PURL = "pkg:npm/%40scope/foo"
	subjects := []Subject{{Ref: "a", Name: "@scope/foo", Version: "1.0", Ecosystem: "npm", Type: "npm"}, {Ref: "b", Name: "@scope/foo", Version: "1.1", Ecosystem: "npm", Type: "npm"}}
	store := &fakeStore{records: []vulndb.Record{rec}}
	r, e := Run(context.Background(), store, subjects, Options{})
	if e != nil || len(r.Findings) != 2 || store.calls != 1 {
		t.Fatalf("lookup cache %+v %d %v", r, store.calls, e)
	}
}
func TestSeverityAndFixedFilters(t *testing.T) {
	s := Subject{Ref: "a", Name: "foo", Version: "1.0", Ecosystem: "npm", Type: "npm"}
	rec := advisory("npm", "foo", "2.0")
	rec.Database = map[string]any{"severity": "low"}
	for _, tt := range []struct {
		opts Options
		want int
	}{{Options{MinSeverity: "medium"}, 0}, {Options{MinSeverity: "low"}, 1}, {Options{OnlyFixed: true}, 1}} {
		r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{s}, tt.opts)
		if e != nil || len(r.Findings) != tt.want {
			t.Fatalf("filter %+v: %+v %v", tt.opts, r, e)
		}
	}
	rec.Affected[0].Ranges[0].Events = []vulndb.Event{{Introduced: "0"}}
	r, _ := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{s}, Options{OnlyFixed: true})
	if len(r.Findings) > 0 {
		t.Fatal("unfixed advisory survived only-fixed")
	}
}
func TestHostFixtureOSParity(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture or external integration; run without -short")
	}
	for _, name := range []string{"../../host.cdx.json", "../../host.spdx.json"} {
		if _, e := os.Stat(name); os.IsNotExist(e) {
			t.Skip("host fixture absent")
		}
		d, e := LoadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if d.Context.OS == nil || d.Context.OS.ID != "debian" || d.Context.OS.VersionID != "13" {
			t.Fatalf("%s OS context %+v", name, d.Context.OS)
		}
		for _, s := range d.Subjects {
			if s.Ecosystem == "Debian" && s.Release != "13" {
				t.Fatalf("%s package %s release %q", name, s.Name, s.Release)
			}
		}
	}
}
func TestCycloneDXUpgradeDropsStaleSignature(t *testing.T) {
	d, e := Load([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"signature":{"algorithm":"RS256","value":"obsolete"},"components":[]}`))
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if e := Write(&b, "cyclonedx", Report{}, d); e != nil {
		t.Fatal(e)
	}
	var out map[string]any
	if e := json.Unmarshal(b.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out["specVersion"] != "1.6" || out["signature"] != nil || out["$schema"] == nil {
		t.Fatalf("bad upgraded document %v", out)
	}
	if d.Raw["signature"] == nil {
		t.Fatal("mutated source signature")
	}
}
