package report

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func fixture() Input {
	subjects := []match.Subject{{Ref: "a", Name: "alpha|pkg", Version: "1.0", Ecosystem: "Debian", Release: "13", PURL: purl.PURL{Type: "deb", Namespace: "debian", Name: "alpha", Version: "1.0"}}, {Ref: "b", Name: "beta", Version: "1.0.0", Ecosystem: "npm"}, {Ref: "c", Name: "gamma", Version: "1", Ecosystem: "Alpine", Release: "3.20"}}
	fs := []match.Finding{
		{ID: "OSV-unknown", Subject: subjects[2], Severity: "UNKNOWN", Record: match.RecordSummary{Source: "osv", Summary: "unknown"}},
		{ID: "CVE-2026-0002", RelatedIDs: []string{"DEBIAN-2026-2", "GHSA-withdrawn-related"}, Subject: subjects[0], Severity: "HIGH", Score: 7.5, FixedIn: []string{"1.9"}, MatchedBy: "source", Confidence: "high", Record: match.RecordSummary{Source: "debian-tracker", Summary: "<script>alert('x')</script> | bad\x1b[31m text", Withdrawn: "2026-01-01"}, Assessment: &assessment.Result{Status: assessment.NeedsReview, Reason: "reason <script> & |"}},
		{ID: "CVE-2026-0001", Subject: subjects[0], Severity: "CRITICAL", Score: 9.8, FixedIn: []string{"1.10"}, Vector: "CVSS:3.1/AV:N", Record: match.RecordSummary{Source: "debian-tracker", Summary: strings.Repeat("한", 250)}},
		{ID: "GHSA-0003", Subject: subjects[1], Severity: "MEDIUM", Score: 5.0, Record: match.RecordSummary{Source: "osv", Summary: "medium", References: []string{"javascript:alert(1)", "https://example.org/a"}}},
		{ID: "CVE-2026-0004", RelatedIDs: []string{"ALPINE-2026-4"}, Subject: subjects[2], Severity: "LOW", Score: 1.0, Record: match.RecordSummary{Source: "alpine-secdb", Summary: "low"}},
	}
	return Input{Report: match.Report{Schema: match.FindingsSchema, GeneratedAt: time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC), Findings: fs, Subjects: 3, Matched: 3, Skipped: map[string]int{"withdrawn": 1, "permission": 2}, DB: vulndb.Meta{Records: 100, UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Sources: []vulndb.SourceMeta{{Name: "osv", Records: 100}}}}, Target: "target <script>", SBOMPath: "host.cdx.json", GeneratedAt: time.Date(2026, 1, 2, 12, 0, 0, 0, time.FixedZone("KST", 9*3600)), ToolVersion: "test", Scan: &scan.ScanMetadata{Partial: true, EUID: 1000, PermissionDenied: 2, MetadataSkipped: 3, Excluded: []string{"/proc"}, InContainer: true}, OS: &scan.OSRelease{ID: "debian", VersionID: "13"}, Image: &scan.ImageMetadata{ID: "sha256:abc"}, Host: &scan.HostMetadata{Hostname: "host"}, Options: match.Options{MinSeverity: "LOW", FailOn: "HIGH"}}
}
func renderTest(t *testing.T, format string, in Input) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, format, in); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestJSONSchemaSummaryOrderingAndRollups(t *testing.T) {
	in := fixture()
	before, _ := json.Marshal(in)
	b := renderTest(t, "json", in)
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != 1 || d.GeneratedBy.Name != "bscan" || d.GeneratedBy.Version != "test" {
		t.Fatalf("schema/generator: %+v", d)
	}
	if d.GeneratedAt.Format(time.RFC3339) != "2026-01-02T03:00:00Z" {
		t.Fatal(d.GeneratedAt)
	}
	if d.Summary.Subjects != 3 || d.Summary.Matched != 3 || d.Summary.Findings != 5 || len(d.Summary.BySeverity) != 6 || d.Summary.BySeverity["UNKNOWN"] != 1 || d.Summary.BySeverity["NEGLIGIBLE"] != 0 {
		t.Fatal(d.Summary)
	}
	want := []string{"CVE-2026-0001", "CVE-2026-0002", "GHSA-0003", "CVE-2026-0004", "OSV-unknown"}
	for i, f := range d.Findings {
		if f.ID != want[i] {
			t.Fatalf("order %d: %s", i, f.ID)
		}
	}
	if len([]rune(d.Findings[0].Summary)) != 200 || strings.Contains(d.Findings[1].Summary, "\x1b") {
		t.Fatal("summary not bounded/sanitized")
	}
	if d.Findings[1].AssessmentStatus != "needs_review" || d.Findings[1].Withdrawn == "" || len(d.Findings[1].RelatedIDs) != 2 {
		t.Fatal(d.Findings[1])
	}
	if d.Packages[0].WorstFix != "1.10" || len(d.TopPackages) != 1 || d.TopPackages[0].BySeverity["CRITICAL"] != 1 {
		t.Fatal(d.Packages)
	}
	if d.Scan.ExcludedCount != 1 || d.Scan.MetadataSkipped != 3 || d.OS.ID != "debian" || d.Options.FailOn != "HIGH" {
		t.Fatal("context lost")
	}
	after, _ := json.Marshal(in)
	if !bytes.Equal(before, after) {
		t.Fatal("render mutated input")
	}
	all := string(b)
	for _, s := range []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-0001", "https://osv.dev/vulnerability/GHSA-0003", "https://security-tracker.debian.org/tracker/CVE-2026-0002", "https://security.alpinelinux.org/vuln/CVE-2026-0004"} {
		if !strings.Contains(all, s) {
			t.Errorf("missing link %s", s)
		}
	}
	if strings.Contains(all, "javascript:") {
		t.Fatal("unsafe reference retained")
	}
}
func TestLoadActualMatcherJSON(t *testing.T) {
	in := fixture()
	in.Report.BySeverity = map[string]int{}
	var b bytes.Buffer
	if err := match.Write(&b, "json", in.Report, match.Document{}); err != nil {
		t.Fatal(err)
	}
	r, err := LoadMatchJSON(&b)
	if err != nil || !reflect.DeepEqual(r, in.Report) {
		t.Fatalf("roundtrip err=%v report=%+v", err, r)
	}
	b.Reset()
	if err := match.Write(&b, "json", in.Report, match.Document{}); err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(b.String())
	raw = raw[:len(raw)-1] + `,"future_field":{"ok":true}}`
	if _, err := LoadMatchJSON(strings.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", `null`, `{}`, `[]`, `{"schema":"bscan-findings/1","findings":"bad"}`, `{"Findings":[]} {}`, `{"Findings":[]} junk`, string(renderTest(t, "json", in))} {
		if _, err := LoadMatchJSON(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted invalid input %s", bad)
		}
	}
}
func TestHTMLStructureAndEscaping(t *testing.T) {
	s := string(renderTest(t, "html", fixture()))
	balancedHTML(t, s)
	for _, want := range []string{"&lt;script&gt;", "&lt;/script&gt;", "prefers-color-scheme:dark", "overflow-wrap:anywhere", "fieldset{min-width:0}", "data-sort=", "severity-filters", "data-package=", "Assessment reason", "metadata-skipped=3", "&lt;script&gt; &amp; |"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"<script>alert", `src="http`, `href="https://cdn`, `<script src`, "\x1b", "ZgotmplZ"} {
		if strings.Contains(s, bad) {
			t.Errorf("unsafe/broken HTML %q", bad)
		}
	}
}

// A small tokenizer for the finite set of elements this renderer emits. Script
// and style raw text are removed first so JS comparisons are not HTML tokens.
func balancedHTML(t *testing.T, s string) {
	t.Helper()
	s = regexp.MustCompile(`(?s)(<script\b[^>]*>).*?(</script>)`).ReplaceAllString(s, "$1$2")
	s = regexp.MustCompile(`(?s)(<style\b[^>]*>).*?(</style>)`).ReplaceAllString(s, "$1$2")
	tags := regexp.MustCompile(`</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>`).FindAllStringSubmatch(s, -1)
	var stack []string
	void := map[string]bool{"meta": true, "input": true, "br": true}
	for _, m := range tags {
		name := strings.ToLower(m[1])
		if void[name] {
			continue
		}
		if strings.HasPrefix(m[0], "</") {
			if len(stack) == 0 || stack[len(stack)-1] != name {
				t.Fatalf("unbalanced %s, stack %v", m[0], stack)
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, name)
		}
	}
	if len(stack) > 0 {
		t.Fatalf("unclosed tags %v", stack)
	}
}
func TestLargeHTMLCompressedCompleteAndChunked(t *testing.T) {
	in := fixture()
	in.Report.Findings = make([]match.Finding, 10001)
	base := fixture().Report.Findings[1]
	for i := range in.Report.Findings {
		f := base
		f.ID = fmt.Sprintf("CVE-2026-%06d", i)
		in.Report.Findings[i] = f
	}
	s := string(renderTest(t, "html", in))
	balancedHTML(t, s)
	if strings.Count(s, "<tr data-severity=") != pageSize {
		t.Fatal("large report eagerly rendered all rows")
	}
	m := regexp.MustCompile(`const compressed=("[A-Za-z0-9+/=]+")`).FindStringSubmatch(s)
	if len(m) != 2 {
		t.Fatal("missing compressed dataset")
	}
	var encoded string
	if err := json.Unmarshal([]byte(m[1]), &encoded); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	var payload struct {
		Rows     [][]string `json:"rows"`
		Packages []Package  `json:"packages"`
	}
	if err := json.NewDecoder(gz).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	rows := payload.Rows
	if len(payload.Packages) != 1 {
		t.Fatal("missing package payload")
	}
	if len(rows) != 10001 || rows[10000][3] != "CVE-2026-010000" || rows[0][11] != clean(base.Record.Summary) {
		t.Fatal("dataset truncated or escaped incorrectly")
	}
	if len(s) > 2<<20 {
		t.Fatalf("repetitive report too large: %d", len(s))
	}
}
func TestCSVRoundtripAndMetadata(t *testing.T) {
	records, err := csv.NewReader(bytes.NewReader(renderTest(t, "csv", fixture()))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 6 || len(records[0]) != len(columns)+1 {
		t.Fatalf("rows: %v", records)
	}
	if records[2][11] != clean(fixture().Report.Findings[1].Record.Summary) || records[2][14] != "reason <script> & |" {
		t.Fatal("CSV changed fields")
	}
	var d Document
	if err := json.Unmarshal([]byte(records[1][len(columns)]), &d); err != nil {
		t.Fatal(err)
	}
	if d.Summary.Findings != 5 || len(d.Packages) != 3 || d.Scan.MetadataSkipped != 3 {
		t.Fatal("CSV metadata missing")
	}
	if records[2][len(columns)] != "" {
		t.Fatal("metadata repeated")
	}
}
func TestMarkdownEscapeAliasAndCap(t *testing.T) {
	in := fixture()
	b := renderTest(t, "markdown", in)
	if !bytes.Equal(b, renderTest(t, "md", in)) {
		t.Fatal("md alias differs")
	}
	s := string(b)
	for _, want := range []string{`alpha\|pkg`, `&lt;script&gt;`, `## Per-package rollup`, `## Top 20 packages`, `metadata-skipped=3`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "<script>") {
		t.Fatal("raw HTML in markdown")
	}
	in.Report.Findings = make([]match.Finding, 1001)
	for i := range in.Report.Findings {
		in.Report.Findings[i] = fixture().Report.Findings[1]
	}
	s = string(renderTest(t, "markdown", in))
	if !strings.Contains(s, "[Download the complete JSON](report.json)") {
		t.Fatal("missing truncation note")
	}
	if strings.Count(s, "| CVE-2026-0002 |") != 1000 {
		t.Fatal("finding cap incorrect")
	}
}
func TestSARIFRequiredFieldsAndLogicalLocations(t *testing.T) {
	in := fixture()
	in.Report.Findings = append(in.Report.Findings, in.Report.Findings[1])
	var doc map[string]any
	if err := json.Unmarshal(renderTest(t, "sarif", in), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" || doc["$schema"] == "" {
		t.Fatal(doc)
	}
	runs := array(doc["runs"])
	if len(runs) != 1 {
		t.Fatal(runs)
	}
	run := object(runs[0])
	driver := object(object(run["tool"])["driver"])
	rules := array(driver["rules"])
	results := array(run["results"])
	if driver["name"] != "bscan" || len(rules) != 5 || len(results) != 6 {
		t.Fatal(driver)
	}
	for _, v := range results {
		r := object(v)
		idx := int(r["ruleIndex"].(float64))
		if object(rules[idx])["id"] != r["ruleId"] || str(object(r["message"]), "text") == "" {
			t.Fatal(r)
		}
		level := str(r, "level")
		if level != "error" && level != "warning" && level != "note" {
			t.Fatal(level)
		}
		loc := object(array(r["locations"])[0])
		if _, ok := loc["physicalLocation"]; ok {
			t.Fatal("unexpected file location")
		}
		if str(object(array(loc["logicalLocations"])[0]), "fullyQualifiedName") == "" {
			t.Fatal(loc)
		}
	}
	first := object(array(object(results[0])["locations"])[0])
	if !strings.HasPrefix(str(object(array(first["logicalLocations"])[0]), "fullyQualifiedName"), "pkg:deb/") {
		t.Fatal(first)
	}
	if object(object(rules[0])["properties"])["security-severity"] != "9.8" {
		t.Fatal(rules[0])
	}
	if object(object(run["properties"])["report"])["report_schema_version"] != float64(1) {
		t.Fatal("missing metadata")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestRenderErrorsAndEmptyReports(t *testing.T) {
	for _, format := range []string{"html", "markdown", "json", "csv", "sarif"} {
		t.Run(format, func(t *testing.T) {
			if err := Render(brokenWriter{}, format, fixture()); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("lost write error: %v", err)
			}
			in := fixture()
			in.Report = match.Report{}
			if len(renderTest(t, format, in)) == 0 {
				t.Fatal("empty output")
			}
		})
	}
	if err := Render(io.Discard, "invalid", fixture()); err == nil {
		t.Fatal("invalid format accepted")
	}
}
func TestRollupTop20AndIncomparableVersions(t *testing.T) {
	in := fixture()
	in.Report.Findings = nil
	for i := 0; i < 25; i++ {
		f := fixture().Report.Findings[2]
		f.Subject.Name = fmt.Sprintf("pkg-%02d", i)
		in.Report.Findings = append(in.Report.Findings, f)
	}
	d := prepare(in)
	if len(d.TopPackages) != 20 || d.TopPackages[0].Name != "pkg-00" || d.TopPackages[19].Name != "pkg-19" {
		t.Fatal(d.TopPackages)
	}
	in.Report.Findings[0].Subject.Ecosystem = "unknown"
	in.Report.Findings[0].FixedIn = []string{"x", "y"}
	d = prepare(in)
	if d.Packages[0].FixNote == "" {
		t.Fatal("incomparable fix not called out")
	}
}

func TestFullMetadataLongTextAndEmptyCSV(t *testing.T) {
	in := fixture()
	in.Report.DB.Sources = append(in.Report.DB.Sources, vulndb.SourceMeta{Name: "last-source-after-long-entry", URL: "https://example.org/" + strings.Repeat("x", 300)})
	in.Report.Findings[1].Assessment.Reason = strings.Repeat("a", 210) + "\x1b[31m reason \x1b]0;hidden title\x07" + strings.Repeat("b", 220)
	in.Report.Findings[1].Subject.Name = strings.Repeat("package", 40)
	wantReason := strings.Repeat("a", 210) + " reason " + strings.Repeat("b", 220)
	d := prepare(in)
	if d.Findings[1].AssessmentReason != wantReason || d.Findings[1].Package != in.Report.Findings[1].Subject.Name {
		t.Fatal("long explanation or identity truncated")
	}
	for _, f := range d.Findings {
		if !strings.HasPrefix(f.PURL, "pkg:") {
			t.Fatal("missing logical purl")
		}
	}
	if d.Findings[0].Summary != strings.Repeat("한", 200) {
		t.Fatal("summary must retain first 200 characters")
	}
	for _, format := range []string{"html", "markdown"} {
		s := string(renderTest(t, format, in))
		if !strings.Contains(s, "last-source-after-long-entry") || !strings.Contains(s, strings.Repeat("x", 300)) {
			t.Fatalf("%s truncated metadata", format)
		}
	}
	in.Report.Findings = nil
	records, err := csv.NewReader(bytes.NewReader(renderTest(t, "csv", in))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !strings.Contains(records[0][len(columns)], `"report_schema_version":1`) {
		t.Fatal("empty CSV loses report context")
	}
}
func TestSeverityAliasesAndSanitizeBoundaries(t *testing.T) {
	for input, want := range map[string]string{"MODERATE": "MEDIUM", "NONE": "NEGLIGIBLE", "INFO": "NEGLIGIBLE", "unexpected": "UNKNOWN"} {
		if severity(input) != want {
			t.Fatalf("%s => %s", input, severity(input))
		}
	}
	prefix := strings.Repeat("x", 199)
	for _, escape := range []string{"\x1b[31m", "\u009b31m", "\x1b]title with spaces\x07", "\x1bPtitle\x1b\\"} {
		if got := clean(prefix + escape + "tail"); got != prefix+"tail" {
			t.Fatalf("escape crossing chunk boundary: %q", got)
		}
	}
}
