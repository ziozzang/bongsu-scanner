package vulndb

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMergeOrdersRFC3339TimestampsByInstant(t *testing.T) {
	a := Record{
		Published: "2025-01-01T01:00:00+02:00", // 2024-12-31 23:00 UTC
		Modified:  "2025-01-01T01:00:00+02:00",
	}
	b := Record{
		Published: "2024-12-31T23:30:00Z",
		Modified:  "2024-12-31T23:30:00Z",
	}
	Merge(&a, &b)
	if a.Published != "2025-01-01T01:00:00+02:00" {
		t.Fatalf("wrong earliest publication instant: %s", a.Published)
	}
	if a.Modified != "2024-12-31T23:30:00Z" {
		t.Fatalf("wrong latest modification instant: %s", a.Modified)
	}
}

func TestOSVRetainsLateEnvironmentalConditions(t *testing.T) {
	details := "Requires a remotely accessible service.\n" + strings.Repeat("Technical description. ", 200) + "\nOnly Windows hosts with feature X enabled are affected."
	var v osvVuln
	if err := json.Unmarshal([]byte(osvFixture("CVE-2026-1234", "npm", "example")), &v); err != nil {
		t.Fatal(err)
	}
	v.Details = details
	r, ok := ConvertOSV(&v, SourceOSV)
	if !ok || r.Details != details || r.DetailsTruncated {
		t.Fatalf("description lost conditions: %+v", r)
	}
	if !strings.Contains(r.Details, "remotely accessible") || !strings.Contains(r.Details, "Only Windows") {
		t.Fatal("environmental prerequisites missing")
	}
}

func TestDescriptionLimitAndPersistence(t *testing.T) {
	for _, text := range []string{strings.Repeat("x", MaxDetails), strings.Repeat("x", MaxDetails+1), strings.Repeat("환", MaxDetails/3+10), strings.Repeat("😀", MaxDetails/4+10)} {
		var v osvVuln
		if err := json.Unmarshal([]byte(osvFixture("CVE-2026-1234", "npm", "example")), &v); err != nil {
			t.Fatal(err)
		}
		v.Details = text
		r, ok := ConvertOSV(&v, SourceOSV)
		if !ok {
			t.Fatal("conversion failed")
		}
		if len(r.Details) > MaxDetails || !utf8.ValidString(r.Details) {
			t.Fatalf("invalid bounded UTF8: %d bytes", len(r.Details))
		}
		if r.DetailsTruncated != (len(text) > MaxDetails) {
			t.Fatalf("incorrect truncation flag: %+v", r.DetailsTruncated)
		}
		if r.DetailsTruncated && !strings.HasSuffix(r.Details, "...") {
			t.Fatal("missing truncation marker")
		}
		path := filepath.Join(t.TempDir(), "records.gz")
		if err := writeRecords(path, []*Record{r}); err != nil {
			t.Fatal(err)
		}
		if err := readRecords(path, func(got *Record) error {
			if got.Details != r.Details || got.DetailsTruncated != r.DetailsTruncated {
				t.Error("description metadata lost in storage")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var legacy Record
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-1234","details":"complete old record","affected":[]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.DetailsTruncated || DetailsMayBeTruncated(legacy) {
		t.Fatal("old complete record was flagged")
	}
}

func TestLegacyDescriptionTruncationHeuristic(t *testing.T) {
	for n := 2048; n <= 2051; n++ {
		r := Record{Details: strings.Repeat("x", n-3) + "..."}
		if !DetailsMayBeTruncated(r) {
			t.Errorf("legacy length %d missed", n)
		}
	}
	for _, r := range []Record{{Details: "normal ending..."}, {Details: strings.Repeat("x", 2048)}, {Details: strings.Repeat("x", 2049) + "..."}} {
		if DetailsMayBeTruncated(r) {
			t.Errorf("unexpected heuristic match length=%d", len(r.Details))
		}
	}
	if !DetailsMayBeTruncated(Record{Details: "short", DetailsTruncated: true}) {
		t.Fatal("explicit flag ignored")
	}
}

func TestMergeSelectsFullestDescriptionAndFlag(t *testing.T) {
	cases := []struct {
		a, b Record
		want string
		cut  bool
	}{
		{Record{Details: "short"}, Record{Details: "long complete description"}, "long complete description", false},
		{Record{Details: "long but truncated description...", DetailsTruncated: true}, Record{Details: "complete"}, "complete", false},
		{Record{Details: "prefix...", DetailsTruncated: true}, Record{Details: "longer prefix...", DetailsTruncated: true}, "longer prefix...", true},
		{Record{Details: strings.Repeat("x", 2048) + "..."}, Record{Details: "complete"}, "complete", false},
		{Record{}, Record{Details: strings.Repeat("x", 2048) + "..."}, strings.Repeat("x", 2048) + "...", false},
	}
	for _, c := range cases {
		for _, reverse := range []bool{false, true} {
			a, b := c.a, c.b
			if reverse {
				a, b = b, a
			}
			Merge(&a, &b)
			if a.Details != c.want || a.DetailsTruncated != c.cut {
				t.Errorf("reverse=%v got length=%d cut=%v want length=%d cut=%v", reverse, len(a.Details), a.DetailsTruncated, len(c.want), c.cut)
			}
		}
	}
}
