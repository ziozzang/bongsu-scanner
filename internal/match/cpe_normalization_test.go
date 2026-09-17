package match

import (
	"context"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestCPENormalizedMatching(t *testing.T) {
	for _, tt := range []struct {
		name, subject, criteria, version, ecosystem string
		want                                        int
	}{
		{"escaped version", `a:vendor:product:1.0.0\+7`, `a:vendor:product:1.0.0\+7`, "1.0.0+7", "", 1},
		{"literal question", `a:vendor:product\?:1`, `a:vendor:product\?:1`, "1", "", 1},
		{"literal star", `a:vendor:product\*:1`, `a:vendor:product\*:1`, "1", "", 1},
		{"literal version", `a:vendor:product:1.0\?`, `a:vendor:product:1.0\?`, "1.0?", "", 1},
		{"case", `a:Vendor:Product:1RC`, `a:vendor:product:1rc`, "1RC", "", 1},
		{"escaped colon", `a:vendor:product\:name:1`, `a:vendor:product\:name:1`, "1", "", 1},
		{"different literal", `a:vendor:productx:1`, `a:vendor:product\?:1`, "1", "", 0},
		{"wildcard product", `a:vendor:productx:1`, `a:vendor:product?:1`, "1", "", 0},
		{"explicit target mismatch", `a:vendor:product:1:*:*:*:*:windows`, `a:vendor:product:1:*:*:*:*:pypi`, "1", "PyPI", 0},
		{"NA target mismatch", `a:vendor:product:1:*:*:*:*:-`, `a:vendor:product:1:*:*:*:*:pypi`, "1", "PyPI", 0},
		{"ANY target inference", `a:vendor:product:1`, `a:vendor:product:1:*:*:*:*:pypi`, "1", "PyPI", 1},
		{"literal update", `a:vendor:product:1:patch\?`, `a:vendor:product:1:patch\?`, "1", "", 1},
		{"NA differs from literal hyphen", `a:vendor:product:1:\-`, `a:vendor:product:1:-`, "1", "", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			criteria := "cpe:2.3:" + tt.criteria
			attrs, ok := vulndb.CPEAttributes(criteria)
			if !ok {
				t.Fatal("invalid fixture")
			}
			r := advisory("CPE", attrs[1]+":"+attrs[2], "2")
			r.Affected[0].Database = map[string]any{"cpe": criteria, "operator": "OR"}
			s := Subject{Ref: "test", Version: tt.version, Ecosystem: tt.ecosystem, CPE: "cpe:2.3:" + tt.subject}
			report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{s}, Options{CPE: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != tt.want {
				t.Fatalf("findings=%d want=%d", len(report.Findings), tt.want)
			}
		})
	}
}

func TestCPERubyAlias(t *testing.T) {
	r := advisory("CPE", "ruby-lang:ruby", "4")
	r.Affected[0].Database = map[string]any{"cpe": "cpe:2.3:a:ruby-lang:ruby:*", "operator": "OR"}
	s := Subject{Ref: "ruby", Version: "3.2.1", PURL: purl.PURL{Type: "generic", Name: "ruby"}}
	report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{s}, Options{CPE: true})
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestCPEAliasSpellings(t *testing.T) {
	// NVD dictionary vendor:product spellings for every existing alias.
	want := map[string]string{
		"python": "python:python", "cpython": "python:python", "openssl": "openssl:openssl",
		"node": "nodejs:node.js", "nodejs": "nodejs:node.js", "php": "php:php", "ruby": "ruby-lang:ruby",
	}
	if len(cpeAliases) != len(want) {
		t.Fatalf("unaudited aliases: %v", cpeAliases)
	}
	for name, pair := range want {
		attrs, ok := subjectCPE(Subject{PURL: purl.PURL{Type: "generic", Name: name}})
		if !ok || attrs[1].Value+":"+attrs[2].Value != pair {
			t.Errorf("alias %s: %v", name, attrs)
		}
	}
}

func TestCPENormalizedExactVersions(t *testing.T) {
	for _, version := range []string{`1.0.0\+7`, `1.0\?`, `1.0\*`} {
		t.Run(version, func(t *testing.T) {
			raw := "cpe:2.3:a:vendor:product:" + version
			r := advisory("CPE", "vendor:product", "2")
			r.Affected[0].Ranges = nil
			// Earlier NVD caches retained escapes, or dropped literal wildcard versions.
			if version == `1.0.0\+7` {
				r.Affected[0].Versions = []string{version}
			}
			r.Affected[0].Database = map[string]any{"cpe": raw, "operator": "OR"}
			report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{{Ref: "exact", CPE: raw}}, Options{CPE: true})
			if err != nil || len(report.Findings) != 1 || report.Findings[0].Confidence != "high" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}
