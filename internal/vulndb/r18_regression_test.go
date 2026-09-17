package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestR18OSVCVEMapBounds(t *testing.T) {
	var entries []any
	for i := range 257 {
		var severity []any
		severity = append(severity, map[string]any{"type": strings.Repeat("x", 129), "score": "medium"}, map[string]any{"type": "Ubuntu", "score": strings.Repeat("x", 1025)})
		for range 17 {
			severity = append(severity, map[string]any{"type": "Ubuntu", "score": "medium"})
		}
		entries = append(entries, map[string]any{"id": fmt.Sprintf("CVE-2026-%04d", 1000+i), "severity": severity, "unused": strings.Repeat("x", 2048)})
	}
	var v osvVuln
	if err := json.Unmarshal([]byte(`{"id":"USN-8737-1","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"glibc"}}]}`), &v); err != nil {
		t.Fatal(err)
	}
	v.Affected[0].Database = map[string]any{"source": "fixture", "cves_map": map[string]any{"ecosystem": "Ubuntu:22.04:LTS", "cves": entries}}
	r, ok := ConvertOSV(&v, SourceOSV)
	if !ok {
		t.Fatal("conversion failed")
	}
	m, ok := r.Affected[0].Database["cves_map"].(map[string]any)
	if !ok || m["ecosystem"] != "Ubuntu:22.04:LTS" || r.Affected[0].Database["source"] != "fixture" {
		t.Fatalf("metadata lost: %+v", r.Affected)
	}
	cves := m["cves"].([]any)
	if len(cves) != 256 {
		t.Fatalf("CVE count = %d, want 256", len(cves))
	}
	for _, raw := range cves {
		cve := raw.(map[string]any)
		ratings := cve["severity"].([]any)
		if len(ratings) != 16 || cve["unused"] != nil {
			t.Fatalf("unbounded CVE metadata: %+v", cve)
		}
		for _, raw := range ratings {
			if !reflect.DeepEqual(raw, map[string]any{"type": "Ubuntu", "score": "medium"}) {
				t.Fatalf("invalid severity retained: %v", raw)
			}
		}
	}
	if len(v.Affected[0].Database["cves_map"].(map[string]any)["cves"].([]any)) != 257 {
		t.Fatal("input mutated")
	}
}

func TestR18VEXVersionedNotAffected(t *testing.T) {
	doc := vexDecode(t, `{"document":{"title":"acl","tracking":{"id":"CVE-2026-54369"}},"product_tree":{"branches":[{"product":{"product_id":"rhel9","product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:9::baseos"}}}],"relationships":[{"category":"default_component_of","full_product_name":{"product_id":"src"},"product_reference":"acl-0:2.4.0-1.el9_8.src","relates_to_product_reference":"rhel9"},{"category":"default_component_of","full_product_name":{"product_id":"bin"},"product_reference":"acl-0:2.4.0-1.el9_8.x86_64","relates_to_product_reference":"rhel9"}]},"vulnerabilities":[{"cve":"CVE-2026-54369","product_status":{"fixed":["src"],"known_not_affected":["bin"]}}]}`)
	r, err := convertRedHatVEX(context.Background(), doc)
	if err != nil || r == nil {
		t.Fatalf("convert: %v %v", r, err)
	}
	if len(r.Affected) != 2 {
		t.Fatalf("lost source fixed entry: %+v", r.Affected)
	}
	for _, a := range r.Affected {
		if a.Package != "acl" {
			t.Fatalf("package=%q", a.Package)
		}
		if a.Database["redhat_status"] == "not-affected" {
			if !reflect.DeepEqual(a.Versions, []string{"0:2.4.0-1.el9_8"}) || len(a.Ranges) != 0 {
				t.Fatalf("marker lost EVR: %+v", a)
			}
		} else if len(a.Ranges) != 1 || a.Ranges[0].Events[1].Fixed != "0:2.4.0-1.el9_8" {
			t.Fatalf("fixed source lost: %+v", a)
		}
	}
}
