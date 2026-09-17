package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

var columns = []string{"Package", "Version", "Ecosystem", "Vulnerability ID", "Related IDs", "Severity", "Score", "Vector", "Fixed-in", "Matched-by", "Confidence", "Summary", "Links", "Assessment status", "Assessment reason", "PURL", "Source", "Withdrawn", "Distro severity", "Distro status"}

func cells(f Finding) []string {
	return []string{f.Package, f.Version, f.Ecosystem, f.ID, strings.Join(f.RelatedIDs, ", "), f.Severity, strconv.FormatFloat(f.Score, 'f', 1, 64), f.Vector, strings.Join(f.FixedIn, ", "), f.MatchedBy, f.Confidence, f.Summary, strings.Join(f.Links, " "), f.AssessmentStatus, f.AssessmentReason, f.PURL, f.Source, f.Withdrawn, f.DistroSeverity, f.DistroStatus}
}
func metadata(d Document) Document { d.Findings = nil; return d }
func renderCSV(w io.Writer, d Document) error {
	c := csv.NewWriter(w)
	c.UseCRLF = true
	header := append(append([]string{}, columns...), "Report metadata (JSON; first finding only)")
	meta, err := json.Marshal(metadata(d))
	if err != nil {
		return err
	}
	if len(d.Findings) == 0 {
		header[len(columns)] = "Report metadata (JSON): " + string(meta)
	}
	if err := c.Write(header); err != nil {
		return err
	}
	for i, f := range d.Findings {
		row := cells(f)
		extra := ""
		if i == 0 {
			extra = string(meta)
		}
		if err := c.Write(append(row, extra)); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}

const markdownLimit = 1000

func md(s string) string {
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	for _, ch := range []string{"|", "*", "_", "[", "]", "`", "~"} {
		s = strings.ReplaceAll(s, ch, "\\"+ch)
	}
	return s
}
func renderMarkdown(w io.Writer, d Document) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Vulnerability report: %s\n\n", md(d.Target))
	for _, f := range headerFields(d) {
		fmt.Fprintf(&b, "- **%s:** %s\n", md(f.Name), md(f.Value))
	}
	b.WriteString("\n## Summary\n\n| Subjects | Matched packages | Findings |\n| --- | --- | --- |\n")
	fmt.Fprintf(&b, "| %d | %d | %d |\n\n", d.Summary.Subjects, d.Summary.Matched, d.Summary.Findings)
	b.WriteString("| Severity | Count |\n| --- | --- |\n")
	for _, s := range severities {
		fmt.Fprintf(&b, "| %s | %d |\n", s, d.Summary.BySeverity[s])
	}
	b.WriteString("\n## Findings\n\n| " + strings.Join(columns, " | ") + " |\n| " + strings.Repeat("--- | ", len(columns)) + "\n")
	n := len(d.Findings)
	if n > markdownLimit {
		n = markdownLimit
	}
	for _, f := range d.Findings[:n] {
		row := cells(f)
		for i := range row {
			row[i] = md(row[i])
		}
		b.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	if n < len(d.Findings) {
		b.WriteString("\nShowing the first 1,000 findings. [Download the complete JSON](report.json) (render with --format json -o report.json).\n")
	}
	writePackages := func(title string, ps []Package) {
		fmt.Fprintf(&b, "\n## %s\n\n| Package | Ecosystem | CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | UNKNOWN | Worst fix version | Findings without fix | Note |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n", title)
		n := len(ps)
		if n > markdownLimit {
			n = markdownLimit
		}
		for _, p := range ps[:n] {
			fmt.Fprintf(&b, "| %s | %s |", md(p.Name), md(p.Ecosystem))
			for _, s := range severities {
				fmt.Fprintf(&b, " %d |", p.BySeverity[s])
			}
			fmt.Fprintf(&b, " %s | %d | %s |\n", md(p.WorstFix), p.Unfixed, md(p.FixNote))
		}
		if n < len(ps) {
			b.WriteString("\nPackage table capped at 1,000 rows; see [complete JSON](report.json).\n")
		}
	}
	writePackages("Top 20 packages by critical/high", d.TopPackages)
	writePackages("Per-package rollup", d.Packages)
	_, err := io.WriteString(w, b.String())
	return err
}

type field struct{ Name, Value string }

func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }
func headerFields(d Document) []field {
	out := []field{{"Target", d.Target}, {"SBOM file", d.SBOMPath}, {"Generated at (UTC)", d.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")}, {"Tool version", d.GeneratedBy.Version}, {"DB updated_at", d.DB.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")}, {"DB record count", strconv.Itoa(d.DB.Records)}, {"DB sources", sourcesText(d.DB.Sources)}, {"Options", optionsText(d.Options)}, {"Options provenance", d.OptionsNote}, {"Skipped reasons", countsText(d.Summary.Skipped)}}
	for _, warning := range d.MissingCoverage {
		out = append(out, field{"WARNING", warning})
	}
	if d.Scan == nil {
		out = append(out, field{"Scan completeness", "Unknown (no scan metadata supplied)"})
	} else {
		s := d.Scan
		out = append(out, field{"Scan completeness", fmt.Sprintf("partial=%t; permission-denied=%d; metadata-skipped=%d; excluded=%d; euid=%d; in-container=%t; skipped-errors=%d; files-visited=%d; limit-reached=%s", s.Partial, s.PermissionDenied, s.MetadataSkipped, s.ExcludedCount, s.EUID, s.InContainer, s.SkippedErrors, s.FilesVisited, clean(s.LimitReached))})
	}
	if d.OS != nil {
		out = append(out, field{"OS", osText(d.OS)})
	}
	if d.Image != nil {
		out = append(out, field{"Image", imageText(d.Image)})
	}
	if d.Host != nil {
		out = append(out, field{"Host", hostText(d.Host)})
	}
	return out
}

// sourcesText lists feeds as "name [ecosystems] url (records)" without
// ETags, timestamps, or JSON punctuation.
func sourcesText(sources []vulndb.SourceMeta) string {
	if len(sources) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		label := clean(s.Name)
		if len(s.Ecosystems) > 0 {
			label += " [" + clean(strings.Join(s.Ecosystems, ", ")) + "]"
		}
		if s.URL != "" {
			label += " " + clean(s.URL)
		}
		label += fmt.Sprintf(" (%d records", s.Records)
		if s.Error != "" {
			label += "; error: " + clean(s.Error)
		}
		parts = append(parts, label+")")
	}
	return strings.Join(parts, "; ")
}

func optionsText(o match.Options) string {
	var parts []string
	if o.SeveritySource != "" {
		parts = append(parts, "severity-source="+clean(o.SeveritySource))
	}
	if o.MinSeverity != "" {
		parts = append(parts, "min-severity="+clean(o.MinSeverity))
	}
	if o.FailOn != "" {
		parts = append(parts, "fail-on="+clean(o.FailOn))
	}
	if o.OnlyFixed {
		parts = append(parts, "only-fixed")
	}
	if o.IncludeUnimportant {
		parts = append(parts, "include-unimportant")
	}
	if o.Details {
		parts = append(parts, "details")
	}
	if len(o.IgnoreIDs) > 0 {
		parts = append(parts, "ignore="+clean(strings.Join(o.IgnoreIDs, ",")))
	}
	if len(parts) == 0 {
		return "defaults"
	}
	return strings.Join(parts, "; ")
}

func countsText(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", clean(k), m[k]))
	}
	return strings.Join(parts, "; ")
}

func osText(o *scan.OSRelease) string {
	label := clean(o.ID)
	if o.VersionID != "" {
		label += " " + clean(o.VersionID)
	}
	if o.Codename != "" {
		label += " (" + clean(o.Codename) + ")"
	}
	if o.PrettyName != "" {
		label += " — " + clean(o.PrettyName)
	}
	return label
}

func imageText(i *scan.ImageMetadata) string {
	var parts []string
	if len(i.Tags) > 0 {
		parts = append(parts, "tags="+clean(strings.Join(i.Tags, ",")))
	}
	if i.ID != "" {
		parts = append(parts, "id="+clean(i.ID))
	}
	if i.Digest != "" {
		parts = append(parts, "digest="+clean(i.Digest))
	}
	if i.OS != "" || i.Architecture != "" {
		p := clean(i.OS) + "/" + clean(i.Architecture)
		if i.Variant != "" {
			p += "/" + clean(i.Variant)
		}
		parts = append(parts, "platform="+p)
	}
	if i.Created != "" {
		parts = append(parts, "created="+clean(i.Created))
	}
	if n := len(i.Layers); n > 0 {
		verified := 0
		for _, l := range i.Layers {
			if l.Verified {
				verified++
			}
		}
		parts = append(parts, fmt.Sprintf("layers=%d (verified %d)", n, verified))
	}
	if i.ContainerID != "" {
		parts = append(parts, "container="+clean(i.ContainerID))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "; ")
}

// hostText omits IP addresses on purpose: reports are shared more widely than
// SBOMs, and the SBOM already carries them when they were collected.
func hostText(h *scan.HostMetadata) string {
	var parts []string
	if h.Hostname != "" {
		parts = append(parts, "hostname="+clean(h.Hostname))
	}
	if h.Kernel != "" {
		parts = append(parts, "kernel="+clean(h.Kernel))
	}
	if h.Architecture != "" {
		parts = append(parts, "arch="+clean(h.Architecture))
	}
	if h.CPUModel != "" || h.CPUCount > 0 {
		parts = append(parts, fmt.Sprintf("cpu=%s x%d", clean(h.CPUModel), h.CPUCount))
	}
	if h.MemoryBytes > 0 {
		parts = append(parts, fmt.Sprintf("memory=%.1f GiB", float64(h.MemoryBytes)/(1<<30)))
	}
	if n := len(h.IPAddresses); n > 0 {
		parts = append(parts, fmt.Sprintf("ip-addresses=%d (omitted)", n))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "; ")
}

func sarifLevel(s string) string {
	switch s {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}
func securityScore(f Finding) string {
	if f.Score > 0 && f.Score <= 10 {
		return strconv.FormatFloat(f.Score, 'f', 1, 64)
	}
	switch f.Severity {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "4.0"
	case "LOW":
		return "0.1"
	default:
		return "0.0"
	}
}
func renderSARIF(w io.Writer, d Document) error {
	rules := []any{}
	results := []any{}
	indices := map[string]int{}
	for _, f := range d.Findings {
		idx, ok := indices[f.ID]
		if !ok {
			idx = len(rules)
			indices[f.ID] = idx
			rule := map[string]any{"id": f.ID, "shortDescription": map[string]string{"text": f.ID}, "fullDescription": map[string]string{"text": f.ID + ": " + f.Summary}, "defaultConfiguration": map[string]string{"level": sarifLevel(f.Severity)}, "properties": map[string]any{"security-severity": securityScore(f), "tags": []string{"security"}}}
			if len(f.Links) > 0 {
				rule["helpUri"] = f.Links[0]
			}
			rules = append(rules, rule)
		} else {
			rule := rules[idx].(map[string]any)
			props := rule["properties"].(map[string]any)
			old, _ := strconv.ParseFloat(props["security-severity"].(string), 64)
			score, _ := strconv.ParseFloat(securityScore(f), 64)
			if score > old {
				props["security-severity"] = securityScore(f)
				rule["defaultConfiguration"] = map[string]string{"level": sarifLevel(f.Severity)}
			}
		}
		location := f.PURL
		if location == "" {
			location = f.Ecosystem + "/" + f.Package + "@" + f.Version
		}
		results = append(results, map[string]any{"ruleId": f.ID, "ruleIndex": idx, "level": sarifLevel(f.Severity), "message": map[string]string{"text": f.ID + " in " + f.Package + "@" + f.Version + ": " + f.Summary}, "locations": []any{map[string]any{"logicalLocations": []any{map[string]string{"fullyQualifiedName": location, "name": f.Package, "kind": "package"}}}}, "properties": f})
	}
	driver := map[string]any{"name": "bscan", "informationUri": "https://github.com/ziozzang/bongsu-scanner", "rules": rules}
	if d.GeneratedBy.Version != "" {
		driver["version"] = d.GeneratedBy.Version
	}
	return json.NewEncoder(w).Encode(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": driver}, "results": results, "properties": map[string]any{"report": metadata(d)}}}})
}
