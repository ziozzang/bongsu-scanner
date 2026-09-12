package match

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type analyzerFunc func(context.Context, assessment.Input) (assessment.Result, error)

func (f analyzerFunc) Analyze(ctx context.Context, in assessment.Input) (assessment.Result, error) {
	return f(ctx, in)
}
func assessmentReport() Report {
	return Report{Subjects: 1, Matched: 1, BySeverity: map[string]int{"HIGH": 1}, Skipped: map[string]int{}, Findings: []Finding{{ID: "CVE-2026-1234", Subject: Subject{Ref: "package-ref", Name: "example", Version: "1.0", Ecosystem: "npm"}, Record: RecordSummary{ID: "CVE-2026-1234", Summary: "Windows path handling", Details: "This vulnerability only affects Windows systems using the legacy path resolver.", References: []string{"https://example.org/CVE-2026-1234"}}, Severity: "HIGH", Score: 8.1, Confidence: "high", MatchedBy: "purl-name"}}}
}
func assessmentDoc(t *testing.T, os string) Document {
	t.Helper()
	raw := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{map[string]any{"type": "operating-system", "name": os, "version": "13"}}, "metadata": map[string]any{"component": map[string]any{"type": "application", "name": "scanned target", "bom-ref": "root-ref", "properties": []any{map[string]any{"name": "bscan:host:architecture", "value": "amd64"}, map[string]any{"name": "bscan:host:hostname", "value": "private-host"}, map[string]any{"name": "bscan:host:ip-addresses", "value": "192.0.2.5"}, map[string]any{"name": "bscan:source", "value": "/private/root/path"}}}}}
	b, e := json.Marshal(raw)
	if e != nil {
		t.Fatal(e)
	}
	d, e := Load(b)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestEnrichScannedEnvironmentAndNoIdentifiers(t *testing.T) {
	for _, osName := range []string{"linux", "windows"} {
		t.Run(osName, func(t *testing.T) {
			report := assessmentReport()
			doc := assessmentDoc(t, osName)
			analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
				if in.Environment.OS != osName || in.Environment.Arch != "amd64" || in.Environment.OSVersion != "13" {
					t.Fatalf("wrong scanned environment %+v", in.Environment)
				}
				b, _ := json.Marshal(in)
				for _, secret := range []string{"private-host", "192.0.2.5", "/private/root/path", "package-ref", "root-ref"} {
					if bytes.Contains(b, []byte(secret)) {
						t.Fatalf("irrelevant inventory data sent: %s", secret)
					}
				}
				if in.Environment.Facts["legacy_resolver"] != "disabled" {
					t.Fatal("declared fact missing")
				}
				status := "likely_affected"
				if osName == "linux" {
					status = "likely_not_affected"
				}
				return assessment.Result{Status: status, Reason: "Advisory explicitly limits the affected platform to Windows", Evidence: []string{"only affects Windows systems"}}, nil
			})
			if e := Enrich(context.Background(), &report, doc, analyzer, assessment.Environment{Facts: map[string]string{"legacy_resolver": "disabled", "hostname": "private-host", "ip_address": "192.0.2.5", "source_path": "/private/root/path"}}, 10); e != nil {
				t.Fatal(e)
			}
			if len(report.Findings) != 1 || report.Findings[0].Severity != "HIGH" || !ShouldFail(report, "HIGH") {
				t.Fatal("LLM changed deterministic finding or exit policy")
			}
		})
	}
}

func TestEnrichUsesEffectiveMatchedPackageVersion(t *testing.T) {
	tests := []struct {
		name, matchedBy, subjectName, subjectVersion, upstream, upstreamVersion string
		wantPackage, wantVersion                                                string
	}{
		{name: "upstream-only", matchedBy: "upstream", subjectName: "libexpat1", upstream: "expat", upstreamVersion: "2.6.0-1", wantPackage: "expat", wantVersion: "2.6.0-1"},
		{name: "binary-source-version", matchedBy: "binary-name", subjectName: "libexpat1", subjectVersion: "2.6.0-1", upstream: "expat", upstreamVersion: "2.6.0-1", wantPackage: "libexpat1", wantVersion: "2.6.0-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := Subject{Name: tt.subjectName, Version: tt.subjectVersion, Ecosystem: "Debian", Upstream: tt.upstream, UpstreamVersion: tt.upstreamVersion}
			report := Report{Findings: []Finding{{ID: "CVE-2026-1234", Subject: subject, MatchedBy: tt.matchedBy, Record: RecordSummary{ID: "CVE-2026-1234"}}}}
			var got assessment.Input
			analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
				got = in
				if in.Package == "" || in.Version == "" {
					t.Fatal("analyzer received an incomplete matched identity")
				}
				return assessment.Result{Status: "needs_review"}, nil
			})
			if err := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); err != nil {
				t.Fatal(err)
			}
			if got.Package != tt.wantPackage || got.Version != tt.wantVersion {
				t.Fatalf("effective identity = %s@%s, want %s@%s", got.Package, got.Version, tt.wantPackage, tt.wantVersion)
			}
			if !reflect.DeepEqual(report.Findings[0].Subject, subject) {
				t.Fatalf("assessment mutated subject: %+v", report.Findings[0].Subject)
			}
		})
	}
}
func TestEnrichMissingEnvironmentAndOverride(t *testing.T) {
	report := assessmentReport()
	var got assessment.Input
	analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
		got = in
		return assessment.Result{Status: "needs_review", Reason: "Target environment is unknown"}, nil
	})
	if e := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); e != nil {
		t.Fatal(e)
	}
	if got.Environment.OS != "" || got.Environment.Arch != "" || got.Environment.OSVersion != "" {
		t.Fatalf("scanner runtime leaked into target environment: %+v", got.Environment)
	}
	doc := assessmentDoc(t, "linux")
	override := assessment.Environment{OS: "windows", OSVersion: "11", Arch: "arm64", Facts: map[string]string{"feature": "enabled"}}
	if e := Enrich(context.Background(), &report, doc, analyzer, override, 1); e != nil {
		t.Fatal(e)
	}
	if got.Environment.OS != "windows" || got.Environment.OSVersion != "11" || got.Environment.Arch != "arm64" || got.Environment.Facts["feature"] != "enabled" {
		t.Fatalf("user overrides lost: %+v", got.Environment)
	}
	override.OSVersion = ""
	if e := Enrich(context.Background(), &report, doc, analyzer, override, 1); e != nil {
		t.Fatal(e)
	}
	if got.Environment.OSVersion != "" {
		t.Fatal("old OS version carried into different overridden OS")
	}
}
func TestEnrichDeduplicatesInputsAndCapsDistinctCalls(t *testing.T) {
	report := assessmentReport()
	duplicate := report.Findings[0]
	duplicate.Subject.Ref = "another-install"
	third := duplicate
	third.ID = "CVE-2026-9999"
	report.Findings = append(report.Findings, duplicate, third)
	calls := 0
	analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
		calls++
		return assessment.Result{Status: "needs_review", Reason: "Check deployment", Evidence: []string{"Windows"}}, nil
	})
	if e := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); e != nil {
		t.Fatal(e)
	}
	if calls != 1 || report.Findings[0].Assessment.Status != "needs_review" || report.Findings[1].Assessment.Status != "needs_review" || report.Findings[2].Assessment.Status != "not_assessed" {
		t.Fatalf("dedup/cap failure %d %+v", calls, report.Findings)
	}
	report.Findings[0].Assessment.Evidence[0] = "changed"
	if report.Findings[1].Assessment.Evidence[0] != "Windows" {
		t.Fatal("duplicate annotations share mutable slices")
	}
	if e := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 0); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("zero cap issued request")
	}
	for _, f := range report.Findings {
		if f.Assessment.Status != "not_assessed" {
			t.Fatal("zero cap not annotated")
		}
	}
}
func TestEnrichErrorsPreserveReportAndFailPolicy(t *testing.T) {
	report := assessmentReport()
	before := report
	before.Findings = append([]Finding(nil), report.Findings...)
	sentinel := errors.New("endpoint unavailable\x1b[2J\nretry later")
	analyzer := analyzerFunc(func(context.Context, assessment.Input) (assessment.Result, error) {
		return assessment.Result{}, sentinel
	})
	err := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 5)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error not returned: %v", err)
	}
	if report.Findings[0].Assessment == nil || report.Findings[0].Assessment.Status != "needs_review" || strings.ContainsAny(report.Findings[0].Assessment.Reason, "\x1b\n") {
		t.Fatal("error annotation unsafe or missing")
	}
	if !ShouldFail(report, "HIGH") {
		t.Fatal("assessment error changed fail-on")
	}
	withoutAnnotation := report
	withoutAnnotation.Findings = append([]Finding(nil), report.Findings...)
	withoutAnnotation.Findings[0].Assessment = nil
	if !reflect.DeepEqual(before, withoutAnnotation) {
		t.Fatalf("assessment changed finding or counters\nbefore=%+v\nafter=%+v", before, withoutAnnotation)
	}
}
func TestEnrichCancellation(t *testing.T) {
	report := assessmentReport()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := Enrich(ctx, &report, Document{}, analyzerFunc(func(context.Context, assessment.Input) (assessment.Result, error) {
		calls++
		return assessment.Result{}, nil
	}), assessment.Environment{}, 1)
	if !errors.Is(err, context.Canceled) || calls != 0 || report.Findings[0].Assessment.Status != "needs_review" {
		t.Fatalf("cancellation %v calls=%d", err, calls)
	}
}
func TestEnrichDescriptionTruncation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		report := assessmentReport()
		if legacy {
			report.Findings[0].Record.Details = strings.Repeat("x", 2048) + "..."
		} else {
			report.Findings[0].Record.DetailsTruncated = true
		}
		var truncated bool
		analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
			truncated = in.DescriptionTruncated
			return assessment.Result{Status: "needs_review"}, nil
		})
		if e := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); e != nil {
			t.Fatal(e)
		}
		if !truncated {
			t.Fatal("description truncation not transmitted")
		}
	}
}
func TestAssessmentImageAndLegacySPDXEnvironment(t *testing.T) {
	d := Document{Format: "cyclonedx", Context: Context{OS: &OSInfo{ID: "debian", VersionID: "13"}}, Raw: map[string]any{"metadata": map[string]any{"component": map[string]any{"properties": []any{map[string]any{"name": "bscan:image:os", "value": "linux"}, map[string]any{"name": "bscan:image:architecture", "value": "arm64"}}}}}}
	env := assessmentEnvironment(d, assessment.Environment{})
	if env.OS != "linux" || env.OSVersion != "13" || env.Arch != "arm64" || env.Facts["distribution"] != "debian" {
		t.Fatalf("image environment %+v", env)
	}
	d = Document{Format: "spdx", Raw: map[string]any{"packages": []any{map[string]any{"SPDXID": "SPDXRef-Root", "packageComment": `bscan host metadata: {"operating_system":"windows","os_version":"11","architecture":"amd64","hostname":"private-host","ip_addresses":["192.0.2.5"]}`}}}}
	env = assessmentEnvironment(d, assessment.Environment{})
	if env.OS != "windows" || env.OSVersion != "11" || env.Arch != "amd64" || len(env.Facts) != 0 {
		t.Fatalf("SPDX environment %+v", env)
	}
}
func TestAssessmentOutputsRemainAdvisory(t *testing.T) {
	report := assessmentReport()
	report.Findings[0].Assessment = &assessment.Result{Status: "likely_not_affected", Reason: "Windows-only\x1b[2J requirement", Evidence: []string{"only affects Windows systems"}, Preconditions: []string{"legacy resolver enabled"}, Checks: []string{"confirm runtime platform"}, Model: "test-model", InputSHA256: "abc", Cached: true}
	doc := Document{Format: "spdx"}
	for _, format := range []string{"table", "json", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if e := Write(&b, format, report, doc); e != nil {
				t.Fatal(e)
			}
			if format == "table" {
				if !strings.Contains(b.String(), "LLM-APPLICABILITY") || !strings.Contains(b.String(), "likely_not_affected") || strings.Contains(b.String(), "\x1b") {
					t.Fatalf("bad assessment table %q", b.String())
				}
				return
			}
			var raw map[string]any
			if e := json.Unmarshal(b.Bytes(), &raw); e != nil {
				t.Fatal(e)
			}
			if format == "json" {
				finding := obj(arr(raw["Findings"])[0])
				if str(obj(finding["assessment"]), "status") == "" && str(obj(finding["assessment"]), "Status") == "" {
					t.Fatal("assessment missing from JSON")
				}
				return
			}
			v := obj(arr(raw["vulnerabilities"])[0])
			if _, ok := v["analysis"]; ok {
				t.Fatal("LLM assessment emitted formal VEX")
			}
			properties := props(v["properties"])
			if properties["bscan:assessment:status"] != "likely_not_affected" || properties["bscan:assessment:model"] != "test-model" {
				t.Fatalf("missing properties %v", properties)
			}
			affected := obj(arr(v["affects"])[0])
			version := obj(arr(affected["versions"])[0])
			if str(version, "status") != "affected" {
				t.Fatal("LLM changed deterministic affected status")
			}
		})
	}
	var b bytes.Buffer
	plain := assessmentReport()
	if e := Write(&b, "json", plain, doc); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.String(), `"assessment"`) {
		t.Fatal("disabled assessment should be omitted")
	}
}

func TestEnrichBoundsAdvisoryTextAndReferences(t *testing.T) {
	report := assessmentReport()
	report.Findings[0].Record.Summary = strings.Repeat("요", 3000)
	report.Findings[0].Record.Details = strings.Repeat("약", 30000)
	for i := 0; i < 40; i++ {
		report.Findings[0].Record.References = append(report.Findings[0].Record.References, "https://example.org/"+strings.Repeat("x", i))
	}
	report.Findings[0].Record.References = append(report.Findings[0].Record.References, "https://example.org/"+strings.Repeat("x", 2048), "file:///private/host")
	analyzer := analyzerFunc(func(_ context.Context, in assessment.Input) (assessment.Result, error) {
		if len(in.Summary) > 8192 || len(in.Description) > 64<<10 || !in.DescriptionTruncated || len(in.References) > 32 {
			t.Fatalf("unbounded input summary=%d description=%d refs=%d truncated=%t", len(in.Summary), len(in.Description), len(in.References), in.DescriptionTruncated)
		}
		if !json.Valid(mustAssessmentJSON(t, in)) {
			t.Fatal("invalid Unicode after truncation")
		}
		for _, ref := range in.References {
			if len(ref) > 2048 || strings.HasPrefix(ref, "file:") {
				t.Fatal("invalid reference retained")
			}
		}
		return assessment.Result{Status: "needs_review"}, nil
	})
	if e := Enrich(context.Background(), &report, Document{}, analyzer, assessment.Environment{}, 1); e != nil {
		t.Fatal(e)
	}
}
func mustAssessmentJSON(t *testing.T, in assessment.Input) []byte {
	t.Helper()
	b, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestAssessmentNormalizesDistributionToOS(t *testing.T) {
	env := assessmentEnvironment(Document{Context: Context{OS: &OSInfo{ID: "debian", VersionID: "13"}}}, assessment.Environment{})
	if env.OS != "linux" || env.OSVersion != "13" || env.Facts["distribution"] != "debian" {
		t.Fatalf("distribution environment %+v", env)
	}
	env = assessmentEnvironment(Document{Context: Context{OS: &OSInfo{ID: "debian", VersionID: "13"}}}, assessment.Environment{OS: "linux"})
	if env.OSVersion != "13" || env.Facts["distribution"] != "debian" {
		t.Fatal("same platform override lost distribution")
	}
}

func TestMixedOSIsUnknownForAssessment(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "cyclonedx",
			raw:  []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"linux","version":"6"},{"type":"operating-system","name":"windows","version":"11"},{"type":"library","bom-ref":"p","name":"p","version":"1","purl":"pkg:npm/p@1"}]}`),
		},
		{
			name: "spdx",
			raw:  []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Linux","name":"linux","versionInfo":"6","primaryPackagePurpose":"OPERATING-SYSTEM"},{"SPDXID":"SPDXRef-Windows","name":"windows","versionInfo":"11","primaryPackagePurpose":"OPERATING-SYSTEM"},{"SPDXID":"SPDXRef-P","name":"p","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/p@1"}]}]}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Load(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if !d.Context.MixedOS || d.Context.OS != nil {
				t.Fatalf("mixed OS was not retained as unknown: %+v", d.Context)
			}
			env := assessmentEnvironment(d, assessment.Environment{})
			if env.OS != "unknown" || env.OSVersion != "" || env.Arch != "" {
				t.Fatalf("mixed OS leaked a target context: %+v", env)
			}
		})
	}
}

func TestAssessmentReferencesStripQueryAndFragment(t *testing.T) {
	refs := assessmentReferences([]vulndb.Reference{
		{URL: "https://example.org/advisory?token=secret-value#private-fragment"},
		{URL: "https://example.org/other#fragment"},
		{URL: "https://user:secret@example.org/private"},
	})
	if !reflect.DeepEqual(refs, []string{"https://example.org/advisory", "https://example.org/other"}) {
		t.Fatalf("references were not privacy-sanitized: %v", refs)
	}
	for _, ref := range refs {
		if strings.Contains(ref, "secret") || strings.Contains(ref, "fragment") || strings.ContainsAny(ref, "?#") {
			t.Fatalf("sensitive URL material retained: %q", ref)
		}
	}
}
