package match

import (
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"testing"
)

func TestCVSSBase(t *testing.T) {
	for _, tt := range []struct {
		v     string
		score float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0},
	} {
		t.Run(tt.v, func(t *testing.T) {
			score, e := CVSSBase(tt.v)
			if e != nil || score != tt.score {
				t.Fatalf("got %.1f, %v want %.1f", score, e, tt.score)
			}
		})
	}
	for _, v := range []string{"CVSS:4.0/AV:N", "CVSS:3.1/AV:N", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, e := CVSSBase(v); e == nil {
			t.Fatalf("invalid vector accepted %s", v)
		}
	}
}
func TestV4PreservesVectorWithoutInventingScore(t *testing.T) {
	v := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	s, n, got := severity(vulndb.Record{Severity: []vulndb.Severity{{Type: "CVSS_V4", Score: v}}}, vulndb.Affected{Database: map[string]any{"severity": "high"}})
	if s != "HIGH" || n != 0 || got != v {
		t.Fatalf("severity %s %f %s", s, n, got)
	}
}

func TestRecordDatabaseSeverity(t *testing.T) {
	s, score, _ := severity(vulndb.Record{Database: map[string]any{"severity": "MODERATE"}}, vulndb.Affected{})
	if s != "MEDIUM" || score != 0 {
		t.Fatalf("record severity: %s %f", s, score)
	}
}
