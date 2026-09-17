package match

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestFindingsJSONContract(t *testing.T) {
	stamp := time.Date(2026, 9, 17, 12, 34, 56, 0, time.FixedZone("KST", 9*3600))
	p, err := purl.Parse("pkg:apk/alpine/openssl@3.1.0-r0?arch=x86_64&distro=alpine-3.20#lib")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), &fakeStore{}, nil, Options{Now: func() time.Time { return stamp }, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s := Subject{CPE: "cpe:2.3:a:test:test:1:*:*:*:*:*:*:*", Ref: "ref", Name: "openssl", Version: "3.1.0-r0", PURL: p, Type: "apk", Ecosystem: "Alpine", Release: "v3.20", Upstream: "openssl", UpstreamVersion: "3.1.0-r0", Properties: map[string]string{"bscan:source": "apk"}}
	r.Subjects, r.Matched = 1, 1
	r.Findings = []Finding{{ID: "CVE-2026-1", RelatedIDs: []string{"ALIAS"}, Subject: s, Record: RecordSummary{ID: "CVE-2026-1", Source: "test", DetailsTruncated: true}, Affected: vulndb.Affected{Ecosystem: "Alpine:v3.20", Package: "openssl"}, MatchedBy: "upstream", FixedIn: []string{"3.2.0-r0"}, Severity: "HIGH", Score: 7.5, Vector: "CVSS:3.1/AV:N", Confidence: "low", DistroSeverity: "high", DistroStatus: "undetermined", Assessment: &assessment.Result{Status: assessment.NeedsReview}}}
	r.BySeverity["HIGH"] = 1
	r.MissingCoverage = []string{"coverage gap"}
	direct, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var streamed bytes.Buffer
	if err := Write(&streamed, "json", r, Document{}); err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	if err := json.Unmarshal(direct, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(streamed.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("direct and streamed schemas differ")
	}
	assertJSONKeys(t, got, "schema", "generated_at", "tool", "severity_policy", "findings", "subjects", "matched", "skipped", "by_severity", "db", "missing_coverage")
	if got["schema"] != FindingsSchema || got["generated_at"] != "2026-09-17T03:34:56Z" {
		t.Fatalf("metadata: %v", got)
	}
	assertJSONKeys(t, got["tool"].(map[string]any), "name", "version")
	f := got["findings"].([]any)[0].(map[string]any)
	assertJSONKeys(t, f, "id", "related_ids", "subject", "record", "affected", "matched_by", "fixed_in", "severity", "score", "vector", "confidence", "distro_severity", "distro_status", "assessment")
	sub := f["subject"].(map[string]any)
	assertJSONKeys(t, sub, "cpe", "ref", "name", "version", "purl", "type", "ecosystem", "release", "upstream", "upstream_version", "properties")
	if sub["purl"] != p.String() {
		t.Fatalf("purl is not a string: %v", sub["purl"])
	}
	var roundtrip Report
	if err := json.Unmarshal(streamed.Bytes(), &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, roundtrip) {
		t.Fatalf("roundtrip changed report: %+v", roundtrip)
	}
}

func assertJSONKeys(t *testing.T, object map[string]any, keys ...string) {
	t.Helper()
	if len(object) != len(keys) {
		t.Fatalf("keys: got %v, want %v", object, keys)
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
}

func TestEmptyFindingsJSON(t *testing.T) {
	for _, stream := range []bool{false, true} {
		var b bytes.Buffer
		var err error
		if stream {
			err = Write(&b, "json", Report{}, Document{})
		} else {
			err = json.NewEncoder(&b).Encode(Report{})
		}
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(b.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"findings": "[]", "subjects": "0", "matched": "0", "skipped": "{}", "by_severity": "{}"} {
			if string(raw[key]) != want {
				t.Errorf("%s = %s", key, raw[key])
			}
		}
		var stamp string
		if err := json.Unmarshal(raw["generated_at"], &stamp); err != nil {
			t.Fatal(err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || parsed.Location() != time.UTC || time.Since(parsed) > time.Minute {
			t.Fatalf("timestamp %q: %v", stamp, err)
		}
		if _, exists := raw["tool"]; exists {
			t.Fatal("unknown tool version should be omitted")
		}
	}
}

func TestSubjectJSONPURLValidationAndOmission(t *testing.T) {
	for _, bad := range []string{`{"purl":{}}`, `{"purl":"not-a-purl"}`, `{"purl":42}`} {
		var s Subject
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	raw, err := json.Marshal(Subject{Ref: "cpe-only", Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, fields, "ref", "name")
	var s Subject
	if err := json.Unmarshal(raw, &s); err != nil || s.PURL.String() != "" {
		t.Fatalf("empty purl: %+v, %v", s, err)
	}
}

func TestFindingJSONOmitsEmptyOptionalFields(t *testing.T) {
	data, err := json.Marshal(Finding{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, fields, "id", "subject", "record", "affected", "matched_by", "severity", "confidence")
}
