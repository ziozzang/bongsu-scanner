package vulndb

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestCPEAttributeClassification(t *testing.T) {
	for _, tt := range []struct {
		raw, value, formatted string
		kind                  CPEAttributeKind
	}{
		{"*", "*", "*", CPEAny},
		{"-", "-", "-", CPENA},
		{`\-`, "-", `\-`, CPELiteral},
		{`\*`, "*", `\*`, CPELiteral},
		{`Product\?`, "product?", `product\?`, CPELiteral},
		{`1.0.0\+7`, "1.0.0+7", "1.0.0+7", CPELiteral},
		{`Pro\:duct\\Name`, `pro:duct\name`, `pro\:duct\\name`, CPELiteral},
		{"Product?", "product?", "product?", CPEPattern},
		{`Product\?*`, "product?*", `product\?*`, CPEPattern},
		{`\VENDOR`, "vendor", "vendor", CPELiteral},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			a, ok := ParseCPEAttribute(tt.raw)
			if !ok || a.Kind != tt.kind || a.Value != tt.value || a.Formatted() != tt.formatted {
				t.Fatalf("attribute=%+v ok=%v", a, ok)
			}
			b, ok := ParseCPEAttribute(a.Formatted())
			if !ok || a != b {
				t.Fatalf("normalization not idempotent: %+v %+v", a, b)
			}
		})
	}
	attrs, ok := ParseCPE(`cpe:2.3:A:Ven\\:Pro\:duct:1\+7`)
	if !ok || len(attrs) != 11 || attrs[0].Value != "a" || attrs[1].Value != `ven\` || attrs[2].Value != "pro:duct" || attrs[3].Value != "1+7" || attrs[10].Kind != CPEAny {
		t.Fatalf("attributes=%+v ok=%v", attrs, ok)
	}
	for _, raw := range []string{"", `broken\`, "unescaped:colon", "with space"} {
		if _, ok := ParseCPEAttribute(raw); ok {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestNVDCPENormalizedVersion(t *testing.T) {
	r := convertNVD(nvdCVE{Configurations: []nvdNode{{Operator: "OR", Matches: []nvdCPEMatch{{Vulnerable: true, Criteria: `cpe:2.3:a:Vendor:Product:1.0.0\+7`}}}}})
	if len(r.Affected) != 1 || r.Affected[0].Package != "vendor:product" || len(r.Affected[0].Versions) != 1 || r.Affected[0].Versions[0] != "1.0.0+7" {
		t.Fatalf("affected=%+v", r.Affected)
	}
}

func TestSQLiteCPENormalizedKeys(t *testing.T) {
	for _, tt := range []struct{ raw, vendor, product string }{
		{`cpe:2.3:a:Vendor:Product:1`, "vendor", "product"},
		{`cpe:2.3:a:vendor:product:1`, "VENDOR", "PRODUCT"},
		{`cpe:2.3:a:vendor:product\+name:1`, "vendor", "product+name"},
		{`cpe:2.3:a:vendor:product+name:1`, "vendor", `product\+name`},
		{`cpe:2.3:a:vendor:product\?:1`, "vendor", `product\?`},
		{`cpe:2.3:a:vendor:product\:name:1`, "vendor", `product\:name`},
	} {
		t.Run(tt.raw+tt.product, func(t *testing.T) {
			dir := t.TempDir()
			attrs, _ := CPEAttributes(tt.raw)
			// Keep the old serialized package spelling to exercise cached NVD records.
			r := &Record{ID: "CVE-2025-1234", Affected: []Affected{{Ecosystem: "CPE", Package: attrs[1] + ":" + attrs[2], Database: map[string]any{"cpe": tt.raw}}}}
			meta := Meta{}
			if err := buildSQLite(context.Background(), dir, map[string]*Record{r.ID: r}, &meta); err != nil {
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
			got, err := st.(CPEStore).LookupCPE(tt.vendor, tt.product)
			if err != nil || len(got) != 1 {
				t.Fatalf("lookup=%v err=%v", got, err)
			}
		})
	}
}

func TestSQLiteRejectsUnnormalizedCPESchema(t *testing.T) {
	dir := readerCatalog(t)
	alterReaderCatalog(t, dir, "PRAGMA user_version=6")
	st, err := Open(dir)
	if st != nil {
		st.Close()
	}
	if !errors.Is(err, ErrUnsupportedCatalog) {
		t.Fatalf("old CPE index must require rebuild: %v", err)
	}
}
