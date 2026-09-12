package match

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestReviewOSVLimits(t *testing.T) {
	for _, tt := range []struct {
		name, version string
		events        []vulndb.Event
		want          bool
	}{
		{"infinity", "1.0.0", []vulndb.Event{{Introduced: "0"}, {Limit: "*"}}, true},
		{"any limit", "3.0.0", []vulndb.Event{{Introduced: "0"}, {Limit: "2.0.0"}, {Limit: "4.0.0"}}, true},
		{"introduction cannot escape", "3.0.0", []vulndb.Event{{Introduced: "0"}, {Limit: "2.0.0"}, {Introduced: "3.0.0"}}, false},
		{"exclusive upper limit", "4.0.0", []vulndb.Event{{Introduced: "0"}, {Limit: "2.0.0"}, {Limit: "4.0.0"}}, false},
		{"fixed before infinity", "2.0.0", []vulndb.Event{{Limit: "*"}, {Fixed: "2.0.0"}, {Introduced: "0"}}, false},
		{"gap before limit", "2.5.0", []vulndb.Event{{Introduced: "0"}, {Fixed: "2.0.0"}, {Introduced: "3.0.0"}, {Limit: "4.0.0"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hit, _, _, _ := affectedVersion("npm", tt.version, vulndb.Affected{Ranges: []vulndb.Range{{Type: "SEMVER", Events: tt.events}}})
			if hit != tt.want {
				t.Fatalf("affected=%t, want %t", hit, tt.want)
			}
		})
	}
}

func TestReviewAffectedSeverity(t *testing.T) {
	for _, recordScore := range []string{"", "4.0", "10.0"} {
		t.Run(recordScore, func(t *testing.T) {
			rec := advisory("npm", "fixture", "2.0.0")
			if recordScore != "" {
				rec.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: recordScore}}
			}
			rec.Affected[0].Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
			r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, []Subject{{Ref: "r", Name: "fixture", Version: "1.0.0", Ecosystem: "npm"}}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) != 1 || r.Findings[0].Severity != "CRITICAL" || r.Findings[0].Score != 9.8 || !ShouldFail(r, "HIGH") {
				t.Fatalf("report=%+v", r)
			}
		})
	}
}

func TestReviewExactVersionIdentifier(t *testing.T) {
	for _, tt := range []struct {
		eco, installed, listed string
		want                   bool
	}{
		{"npm", "1.0.0+safe", "1.0.0+vulnerable", false},
		{"Go", "v1.0.0+safe", "v1.0.0+vulnerable", false},
		{"npm", " v1.0.0+vulnerable ", "1.0.0+vulnerable", true},
		{"npm", "1.0.0", "1.0.0+vulnerable", false},
		{"PyPI", "1.0.0", "1.0", true},
		{"unsupported", " snapshot ", "snapshot", true},
	} {
		t.Run(tt.eco+tt.installed+tt.listed, func(t *testing.T) {
			hit, _, _, _ := affectedVersion(tt.eco, tt.installed, vulndb.Affected{Versions: []string{tt.listed}})
			if hit != tt.want {
				t.Fatalf("affected=%t, want %t", hit, tt.want)
			}
		})
	}
	hit, _, _, _ := affectedVersion("npm", "1.0.0+safe", vulndb.Affected{Ranges: []vulndb.Range{{Type: "SEMVER", Events: []vulndb.Event{{Introduced: "1.0.0+vulnerable"}, {Fixed: "2.0.0"}}}}})
	if !hit {
		t.Fatal("range ordering must still ignore build metadata")
	}
}

func TestReviewAliasesBothDirections(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, declarer := range []int{0, 1} {
			t.Run(fmt.Sprintf("reverse=%t/declarer=%d", reverse, declarer), func(t *testing.T) {
				records := []vulndb.Record{advisory("npm", "fixture", "2.0.0"), advisory("npm", "fixture", "3.0.0")}
				records[0].ID = "CVE-2026-1234"
				records[1].ID = "GHSA-fixture"
				records[declarer].Aliases = []string{records[1-declarer].ID}
				if reverse {
					records[0], records[1] = records[1], records[0]
				}
				r, err := Run(context.Background(), &fakeStore{records: records}, []Subject{{Ref: "r", Name: "fixture", Version: "1.0.0", Ecosystem: "npm"}}, Options{})
				if err != nil {
					t.Fatal(err)
				}
				if len(r.Findings) != 1 || r.Findings[0].ID != "CVE-2026-1234" || len(r.Findings[0].FixedIn) != 2 || len(r.Findings[0].RelatedIDs) != 2 {
					t.Fatalf("findings=%+v", r.Findings)
				}
			})
		}
	}
}

func TestReviewCycloneDXGeneratedRefsResolve(t *testing.T) {
	d, err := Load([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root","components":[{"type":"library","name":"root-child"}]}},"components":[{"type":"library","name":"outer","components":[{"type":"library","name":"inner"}]},{"type":"library","name":"existing","bom-ref":"keep-me"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := Report{}
	for _, s := range d.Subjects {
		r.Findings = append(r.Findings, Finding{ID: "CVE-test", Subject: s, Severity: "HIGH"})
	}
	var out bytes.Buffer
	if err := Write(&out, "cyclonedx", r, d); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	refs := map[string]string{}
	var walk func(map[string]any)
	walk = func(c map[string]any) {
		ref := str(c, "bom-ref")
		if ref == "" {
			t.Errorf("component %s has no bom-ref", str(c, "name"))
		}
		if _, exists := refs[ref]; exists {
			t.Errorf("duplicate ref %q", ref)
		}
		refs[ref] = str(c, "name")
		for _, child := range arr(c["components"]) {
			walk(obj(child))
		}
	}
	for _, c := range arr(raw["components"]) {
		walk(obj(c))
	}
	walk(obj(obj(raw["metadata"])["component"]))
	for _, v := range arr(raw["vulnerabilities"]) {
		for _, a := range arr(obj(v)["affects"]) {
			if _, ok := refs[str(obj(a), "ref")]; !ok {
				t.Errorf("unresolved affects ref %q", str(obj(a), "ref"))
			}
		}
	}
	for _, s := range d.Subjects {
		if refs[s.Ref] != s.Name {
			t.Errorf("ref %s resolves to %q, want %q", s.Ref, refs[s.Ref], s.Name)
		}
	}
	if refs["keep-me"] != "existing" {
		t.Fatal("existing ref changed")
	}
}

func TestReviewConflictingHostOS(t *testing.T) {
	for _, osComponent := range []string{`"name":"debian","version":"12"`, `"name":"ubuntu","version":"24.04"`} {
		d, err := Load([]byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:host:os-version","value":"13"}]}},"components":[{"type":"operating-system",%s},{"type":"library","name":"curl","purl":"pkg:deb/debian/curl@1"},{"type":"library","name":"curl","purl":"pkg:deb/debian/curl@1?distro=debian-13"}]}`, osComponent)))
		if err != nil {
			t.Fatal(err)
		}
		if !d.Context.MixedOS || d.Context.OS != nil || d.Subjects[0].Release != "" || d.Subjects[1].Release != "13" {
			t.Errorf("context=%+v subjects=%+v", d.Context, d.Subjects)
		}
		r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Debian:13", "curl", "2")}}, d.Subjects, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Skipped["release-unknown"] != 1 || len(r.Findings) != 1 {
			t.Errorf("report=%+v", r)
		}
	}
}

func TestReviewDebianSidAndCodename(t *testing.T) {
	for _, v := range []string{"unstable", "sid", "debian-unstable", "debian-sid"} {
		if got := release("Debian", v); got != "sid" {
			t.Errorf("release(%q)=%q", v, got)
		}
	}
	for _, tt := range []struct{ codename, want string }{{"sid", "sid"}, {"trixie", "13"}} {
		for _, component := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/component=%t", tt.codename, component), func(t *testing.T) {
				var raw string
				if component {
					raw = fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"debian","properties":[{"name":"bscan:os:codename","value":%q}]},{"type":"library","name":"curl","purl":"pkg:deb/debian/curl@1"}]}`, tt.codename)
				} else {
					raw = fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:os:codename","value":%q}]}},"components":[{"type":"library","name":"curl","purl":"pkg:deb/debian/curl@1"}]}`, tt.codename)
				}
				d, err := Load([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				if d.Subjects[0].Release != tt.want {
					t.Fatalf("release=%q, want %q", d.Subjects[0].Release, tt.want)
				}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Debian:"+tt.want, "curl", "2")}}, d.Subjects, Options{})
				if err != nil || len(r.Findings) != 1 {
					t.Fatalf("report=%+v err=%v", r, err)
				}
			})
		}
	}
}

func TestReviewHostOSMissingCodenameIsNotConflict(t *testing.T) {
	d, err := Load([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:host:os-version","value":"13"}]}},"components":[{"type":"operating-system","name":"debian","version":"13","properties":[{"name":"bscan:os:codename","value":"trixie"}]},{"type":"library","name":"curl","purl":"pkg:deb/debian/curl@1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Context.MixedOS || d.Context.OS == nil || d.Subjects[0].Release != "13" {
		t.Fatalf("context=%+v subjects=%+v", d.Context, d.Subjects)
	}
}

type reviewQueryStore struct{ fakeStore }

func (s *reviewQueryStore) Lookup(eco, name string) ([]vulndb.Record, error) {
	var records []vulndb.Record
	for _, r := range s.records {
		for _, a := range r.Affected {
			if a.Package == name {
				records = append(records, r)
				break
			}
		}
	}
	return records, nil
}

func TestReviewAliasChainAcrossSubjectLookups(t *testing.T) {
	records := []vulndb.Record{advisory("Debian:13", "source", "2"), advisory("Debian:13", "binary", "3"), advisory("Debian:13", "binary", "4")}
	records[0].ID = "CVE-2026-1234"
	records[0].Aliases = []string{"GHSA-middle"}
	records[1].ID = "GHSA-middle"
	records[1].Aliases = []string{"OSV-last"}
	records[2].ID = "OSV-last"
	s := Subject{Ref: "r", Name: "binary", Upstream: "source", Version: "1", Type: "deb", Ecosystem: "Debian", Release: "13"}
	r, err := Run(context.Background(), &reviewQueryStore{fakeStore{records: records}}, []Subject{s}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "CVE-2026-1234" || len(r.Findings[0].RelatedIDs) != 3 || len(r.Findings[0].FixedIn) != 3 || r.Findings[0].MatchedBy != "upstream" {
		t.Fatalf("findings=%+v", r.Findings)
	}
}
