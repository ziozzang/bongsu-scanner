package vulndb

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOSVUbuntuCVEAlias(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want []string
	}{
		{"UBUNTU-CVE-2016-2781", []string{"CVE-2016-2781"}},
		{"UBUNTU-CVE-2026-1234567", []string{"CVE-2026-1234567"}},
		{"UBUNTU-CVE-2016-2781-extra", nil},
		{"UBUNTU-CVE-2016-123", nil},
		{"USN-1234-1", nil},
	} {
		t.Run(tc.id, func(t *testing.T) {
			var v osvVuln
			if err := json.Unmarshal([]byte(`{"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"coreutils"},"ecosystem_specific":{"ubuntu_priority":"low","priority_reason":"limited impact"}}],"related":["CVE-2016-2781","CVE-2026-9999","USN-1234-1"]}`), &v); err != nil {
				t.Fatal(err)
			}
			v.ID = tc.id
			r, ok := ConvertOSV(&v, SourceOSV)
			if !ok || !reflect.DeepEqual(r.Aliases, tc.want) || !reflect.DeepEqual(r.Related, v.Related) {
				t.Fatalf("converted: %+v", r)
			}
			if r.Affected[0].Specific["priority_reason"] != "limited impact" {
				t.Fatal("reason lost")
			}
			if len(tc.want) > 0 {
				v.Aliases, v.Upstream = tc.want, tc.want
				r, _ = ConvertOSV(&v, SourceOSV)
				if !reflect.DeepEqual(r.Aliases, tc.want) {
					t.Fatalf("duplicate aliases: %v", r.Aliases)
				}
			}
		})
	}
}

func TestUbuntuAliasCVSSPropagation(t *testing.T) {
	var v osvVuln
	if err := json.Unmarshal([]byte(`{"id":"UBUNTU-CVE-2016-2781","upstream":["CVE-2016-2781"],"severity":[{"type":"Ubuntu","score":"low"}],"affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"coreutils"}}]}`), &v); err != nil {
		t.Fatal(err)
	}
	r, ok := ConvertOSV(&v, SourceOSV)
	if !ok {
		t.Fatal("conversion failed")
	}
	index := aliasSeverityIndex{}
	cvss := Severity{Type: "CVSS_V3", Score: "7.5"}
	index.add(&Record{ID: "CVE-2016-2781", Severity: []Severity{cvss}})
	index.apply(r)
	if !reflect.DeepEqual(r.Severity, []Severity{{Type: "Ubuntu", Score: "low"}, cvss}) || !reflect.DeepEqual(r.Affected[0].Severity, []Severity{cvss}) || r.Database["severity_source"] != "alias:CVE-2016-2781" {
		t.Fatalf("vendor priority blocked CVSS propagation: %+v", r)
	}
}
