package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestSecurityReportFormatBoundaries(t *testing.T) {
	for _, format := range []string{"json", "csv", "sarif", "markdown", "md", "html"} {
		for _, count := range []int{0, markdownLimit + 1} {
			t.Run(fmt.Sprintf("%s/%d", format, count), func(t *testing.T) {
				in := Input{GeneratedAt: time.Unix(0, 0).UTC()}
				for i := 0; i < count; i++ {
					in.Report.Findings = append(in.Report.Findings, match.Finding{ID: fmt.Sprintf("ID-%04d", i), Subject: match.Subject{Name: "package", Version: "1", Ecosystem: "npm"}, Severity: "HIGH"})
				}
				raw := renderTest(t, format, in)
				switch format {
				case "json":
					var d Document
					if err := json.Unmarshal(raw, &d); err != nil {
						t.Fatal(err)
					}
					if len(d.Findings) != count || d.Summary.Findings != count {
						t.Fatalf("JSON count = %d, summary = %d", len(d.Findings), d.Summary.Findings)
					}
				case "csv":
					rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
					if err != nil {
						t.Fatal(err)
					}
					if len(rows) != count+1 {
						t.Fatalf("CSV rows = %d", len(rows))
					}
					if count > 0 && rows[count][3] != "ID-1000" {
						t.Fatal("CSV lost final finding")
					}
				case "sarif":
					var doc struct {
						Runs []struct {
							Results []struct {
								RuleID string `json:"ruleId"`
							} `json:"results"`
						} `json:"runs"`
					}
					if err := json.Unmarshal(raw, &doc); err != nil {
						t.Fatal(err)
					}
					if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != count {
						t.Fatal("SARIF lost results")
					}
					if count > 0 && doc.Runs[0].Results[count-1].RuleID != "ID-1000" {
						t.Fatal("SARIF lost final finding")
					}
				case "markdown", "md":
					if got := bytes.Count(raw, []byte("| ID-")); got != min(count, markdownLimit) {
						t.Fatalf("Markdown rows = %d", got)
					}
					if bytes.Contains(raw, []byte("Download the complete JSON")) != (count > markdownLimit) {
						t.Fatal("incorrect Markdown truncation notice")
					}
				case "html":
					if got := bytes.Count(raw, []byte("<tr data-severity=")); got != min(count, pageSize) {
						t.Fatalf("HTML visible rows = %d", got)
					}
					if count > 0 && !bytes.Contains(raw, []byte("ID-1000")) {
						t.Fatal("HTML lost final finding from embedded data")
					}
				}
			})
		}
	}
}

func TestSecurityReportMetadataDetails(t *testing.T) {
	image := &scan.ImageMetadata{Tags: []string{"tag"}, ID: "image", Digest: "digest", OS: "linux", Architecture: "arm64", Variant: "v8", Created: "2026-09-17", Layers: []scan.LayerInfo{{Verified: true}, {}}, ContainerID: "container"}
	if got, want := imageText(image), "tags=tag; id=image; digest=digest; platform=linux/arm64/v8; created=2026-09-17; layers=2 (verified 1); container=container"; got != want {
		t.Fatalf("image = %q", got)
	}
	host := &scan.HostMetadata{Hostname: "host", Kernel: "kernel", Architecture: "arm64", CPUModel: "cpu", CPUCount: 4, MemoryBytes: 2 << 30, IPAddresses: []string{"192.0.2.99"}}
	if got, want := hostText(host), "hostname=host; kernel=kernel; arch=arm64; cpu=cpu x4; memory=2.0 GiB; ip-addresses=1 (omitted)"; got != want {
		t.Fatalf("host = %q", got)
	}
	if hostText(&scan.HostMetadata{}) != "unknown" || imageText(&scan.ImageMetadata{}) != "unknown" {
		t.Fatal("empty metadata not labeled unknown")
	}
	if got := osText(&scan.OSRelease{ID: "debian", VersionID: "13", Codename: "trixie", PrettyName: "Debian GNU/Linux"}); got != "debian 13 (trixie) — Debian GNU/Linux" {
		t.Fatalf("OS = %q", got)
	}
	if got := sourcesText([]vulndb.SourceMeta{{Name: "feed", Records: 3, Error: "bad\x1b[31m"}}); got != "feed (3 records; error: bad)" {
		t.Fatalf("sources = %q", got)
	}
	for severity, want := range map[string]string{"CRITICAL": "9.0", "HIGH": "7.0", "MEDIUM": "4.0", "LOW": "0.1", "UNKNOWN": "0.0"} {
		if got := securityScore(Finding{Severity: severity, Score: 11}); got != want {
			t.Errorf("%s fallback = %q", severity, got)
		}
	}
}

func TestSecurityReportWriteAndMarshalFailures(t *testing.T) {
	// Force CSV's buffered writer to fail during header and finding writes,
	// rather than only when the final buffer is flushed.
	for _, d := range []Document{
		{Target: strings.Repeat("x", 8192)},
		{Findings: []Finding{{Summary: strings.Repeat("x", 8192)}}},
	} {
		if err := renderCSV(brokenWriter{}, d); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("CSV write error = %v", err)
		}
	}
	for _, format := range []string{"csv", "json", "sarif"} {
		if err := Render(io.Discard, format, Input{GeneratedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
			t.Errorf("%s accepted unrepresentable timestamp", format)
		}
	}
}

func TestSecurityMarkdownPackageLimit(t *testing.T) {
	d := Document{Packages: make([]Package, markdownLimit+1)}
	for i := range d.Packages {
		d.Packages[i] = Package{Name: fmt.Sprintf("package-%04d", i), BySeverity: counts()}
	}
	var out bytes.Buffer
	if err := renderMarkdown(&out, d); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "| package-") != markdownLimit || !strings.Contains(out.String(), "Package table capped at 1,000 rows") || strings.Contains(out.String(), "package-1000") {
		t.Fatal("package table limit violated")
	}
}
