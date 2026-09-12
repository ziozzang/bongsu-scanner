// Package report renders match results without changing match.Report's JSON API.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/version"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type Input struct {
	Report      match.Report
	Target      string
	SBOMPath    string
	GeneratedAt time.Time
	ToolVersion string
	Scan        *scan.ScanMetadata
	OS          *scan.OSRelease
	Image       *scan.ImageMetadata
	Host        *scan.HostMetadata
	Options     match.Options
}

var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"}

// Document is report schema version 1. Findings contain presentation fields;
// match.Report remains the interchange format accepted by LoadMatchJSON.
type Document struct {
	SchemaVersion int                 `json:"report_schema_version"`
	GeneratedBy   Generator           `json:"generated_by"`
	Target        string              `json:"target"`
	SBOMPath      string              `json:"sbom_file"`
	GeneratedAt   time.Time           `json:"generated_at"`
	DB            vulndb.Meta         `json:"database"`
	Options       match.Options       `json:"options"`
	OptionsNote   string              `json:"options_note"`
	Summary       Summary             `json:"summary"`
	Scan          *scan.ScanMetadata  `json:"scan"`
	OS            *scan.OSRelease     `json:"os,omitempty"`
	Image         *scan.ImageMetadata `json:"image,omitempty"`
	Host          *scan.HostMetadata  `json:"host,omitempty"`
	Packages      []Package           `json:"packages"`
	TopPackages   []Package           `json:"top_packages"`
	Findings      []Finding           `json:"findings"`
}
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type Summary struct {
	Subjects   int            `json:"subjects"`
	Matched    int            `json:"matched_packages"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	Skipped    map[string]int `json:"skipped"`
}
type Package struct {
	Name       string         `json:"package"`
	Ecosystem  string         `json:"ecosystem"`
	BySeverity map[string]int `json:"by_severity"`
	WorstFix   string         `json:"worst_fix_version"`
	FixNote    string         `json:"fix_note,omitempty"`
	Unfixed    int            `json:"findings_without_fix"`
}
type Finding struct {
	Package          string   `json:"package"`
	Version          string   `json:"version"`
	Ecosystem        string   `json:"ecosystem"`
	PURL             string   `json:"purl"`
	ID               string   `json:"id"`
	RelatedIDs       []string `json:"related_ids"`
	Severity         string   `json:"severity"`
	Score            float64  `json:"score"`
	Vector           string   `json:"vector"`
	FixedIn          []string `json:"fixed_in"`
	MatchedBy        string   `json:"matched_by"`
	Confidence       string   `json:"confidence"`
	Summary          string   `json:"summary"`
	Links            []string `json:"links"`
	AssessmentStatus string   `json:"assessment_status"`
	AssessmentReason string   `json:"assessment_reason"`
	Source           string   `json:"source"`
	Withdrawn        string   `json:"withdrawn,omitempty"`
}

func Render(w io.Writer, format string, in Input) error {
	switch format {
	case "html", "markdown", "md", "json", "csv", "sarif":
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
	d := prepare(in)
	switch format {
	case "html":
		return renderHTML(w, d)
	case "markdown", "md":
		return renderMarkdown(w, d)
	case "csv":
		return renderCSV(w, d)
	case "sarif":
		return renderSARIF(w, d)
	default:
		return json.NewEncoder(w).Encode(d)
	}
}

// LoadMatchJSON accepts one match.Report, including unknown future fields. It
// rejects report envelopes, null, concatenated objects and multi-SBOM arrays.
func LoadMatchJSON(r io.Reader) (match.Report, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return match.Report{}, fmt.Errorf("read match JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return match.Report{}, fmt.Errorf("read match JSON: %w", err)
	}
	found := false
	for key := range raw {
		if strings.EqualFold(key, "report_schema_version") {
			return match.Report{}, fmt.Errorf("expected match JSON, got a rendered report envelope")
		}
		if strings.EqualFold(key, "Findings") {
			found = true
		}
	}
	if !found {
		return match.Report{}, fmt.Errorf("expected a match report with Findings")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return match.Report{}, err
	}
	var rMatch match.Report
	if err := json.Unmarshal(b, &rMatch); err != nil {
		return rMatch, fmt.Errorf("read match JSON: %w", err)
	}
	return rMatch, nil
}

// Sanitize terminal controls without applying the terminal table's 200-rune
// truncation to package identities, URLs, or assessment explanations.
var terminalEscapes = regexp.MustCompile(`(?:\x1b\[|\x{009b})[0-?]*[ -/]*[@-~]|(?:\x1b[\]PX^_]|\x{009d})(?s:.*?)(?:\x07|\x{009c}|\x1b\\|$)|\x1b(?s:.)`)

func clean(s string) string {
	if utf8.RuneCountInString(s) <= httpx.SanitizeLimit {
		return httpx.Sanitize(s)
	}
	s = terminalEscapes.ReplaceAllString(strings.ToValidUTF8(s, ""), "")
	words := strings.Fields(s)
	for i, word := range words {
		runes := []rune(word)
		var b strings.Builder
		for len(runes) > 0 {
			n := min(len(runes), httpx.SanitizeLimit)
			b.WriteString(httpx.Sanitize(string(runes[:n])))
			runes = runes[n:]
		}
		words[i] = b.String()
	}
	return strings.Join(strings.Fields(strings.Join(words, " ")), " ")
}
func cleanList(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = clean(s)
	}
	return out
}
func counts() map[string]int {
	m := map[string]int{}
	for _, s := range severities {
		m[s] = 0
	}
	return m
}
func severity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "MODERATE":
		return "MEDIUM"
	case "NONE", "INFO":
		return "NEGLIGIBLE"
	}
	for _, v := range severities {
		if s == v {
			return v
		}
	}
	return "UNKNOWN"
}
func prepare(in Input) Document {
	if in.GeneratedAt.IsZero() {
		in.GeneratedAt = time.Now()
	}
	d := Document{SchemaVersion: 1, GeneratedBy: Generator{"bscan", clean(in.ToolVersion)}, Target: clean(in.Target), SBOMPath: clean(in.SBOMPath), GeneratedAt: in.GeneratedAt.UTC(), DB: in.Report.DB, Options: in.Options,
		OptionsNote: "Options are caller-supplied; original match JSON does not record options. Zero values from --from do not establish the original matching policy.",
		Summary:     Summary{in.Report.Subjects, in.Report.Matched, len(in.Report.Findings), counts(), in.Report.Skipped}, Scan: in.Scan, OS: in.OS, Image: in.Image, Host: in.Host, Packages: []Package{}, TopPackages: []Package{}, Findings: make([]Finding, 0, len(in.Report.Findings))}
	d.DB.UpdatedAt = d.DB.UpdatedAt.UTC()
	if in.Scan != nil {
		s := *in.Scan
		if s.ExcludedCount < len(s.Excluded) {
			s.ExcludedCount = len(s.Excluded)
		}
		d.Scan = &s
	}
	ordered := append([]match.Finding(nil), in.Report.Findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if match.SeverityRank(a.Severity) != match.SeverityRank(b.Severity) {
			return match.SeverityRank(a.Severity) > match.SeverityRank(b.Severity)
		}
		if a.Subject.Name != b.Subject.Name {
			return a.Subject.Name < b.Subject.Name
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject.Ref < b.Subject.Ref
	})
	packages := map[string]*Package{}
	for _, f := range ordered {
		eco := clean(f.Subject.Ecosystem)
		if f.Subject.Release != "" {
			eco += ":" + clean(f.Subject.Release)
		}
		summary := []rune(f.Record.Summary)
		if len(summary) > 200 {
			summary = summary[:200]
		}
		row := Finding{Package: clean(f.Subject.Name), Version: clean(f.Subject.Version), Ecosystem: eco, PURL: clean(f.Subject.PURL.String()), ID: clean(f.ID), RelatedIDs: cleanList(f.RelatedIDs), Severity: severity(f.Severity), Score: f.Score, Vector: clean(f.Vector), FixedIn: cleanList(f.FixedIn), MatchedBy: clean(f.MatchedBy), Confidence: clean(f.Confidence), Summary: clean(string(summary)), Links: links(f), AssessmentStatus: "not_assessed", Source: clean(f.Record.Source), Withdrawn: clean(f.Record.Withdrawn)}
		if row.PURL == "" {
			row.PURL = (purl.PURL{Type: "generic", Name: row.Package, Version: row.Version, Qualifiers: map[string]string{"ecosystem": eco}}).String()
		}
		if f.Assessment != nil {
			row.AssessmentStatus = clean(f.Assessment.Status)
			row.AssessmentReason = clean(f.Assessment.Reason)
		}
		d.Findings = append(d.Findings, row)
		d.Summary.BySeverity[row.Severity]++
		key := row.Package + "\x00" + eco
		p := packages[key]
		if p == nil {
			p = &Package{Name: row.Package, Ecosystem: eco, BySeverity: counts()}
			packages[key] = p
		}
		p.BySeverity[row.Severity]++
		if len(row.FixedIn) == 0 {
			p.Unfixed++
		}
		for _, fix := range row.FixedIn {
			if fix == "" {
				continue
			}
			if p.WorstFix == "" {
				p.WorstFix = fix
				continue
			}
			cmp, err := version.Compare(f.Subject.Ecosystem, fix, p.WorstFix)
			if err != nil {
				p.FixNote = "Some fix versions are incomparable; highest comparable version shown."
				continue
			}
			if cmp > 0 {
				p.WorstFix = fix
			}
		}
	}
	for _, p := range packages {
		d.Packages = append(d.Packages, *p)
	}
	sort.Slice(d.Packages, func(i, j int) bool {
		if d.Packages[i].Name != d.Packages[j].Name {
			return d.Packages[i].Name < d.Packages[j].Name
		}
		return d.Packages[i].Ecosystem < d.Packages[j].Ecosystem
	})
	for _, p := range d.Packages {
		if p.BySeverity["CRITICAL"]+p.BySeverity["HIGH"] > 0 {
			d.TopPackages = append(d.TopPackages, p)
		}
	}
	sort.SliceStable(d.TopPackages, func(i, j int) bool {
		a, b := d.TopPackages[i], d.TopPackages[j]
		ac, bc := a.BySeverity["CRITICAL"]+a.BySeverity["HIGH"], b.BySeverity["CRITICAL"]+b.BySeverity["HIGH"]
		if ac != bc {
			return ac > bc
		}
		return a.BySeverity["CRITICAL"] > b.BySeverity["CRITICAL"]
	})
	if len(d.TopPackages) > 20 {
		d.TopPackages = d.TopPackages[:20]
	}
	return d
}

func links(f match.Finding) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, id := range append([]string{f.ID}, f.RelatedIDs...) {
		id = clean(id)
		escaped := url.PathEscape(id)
		switch {
		case strings.HasPrefix(id, "CVE-"):
			add("https://nvd.nist.gov/vuln/detail/" + escaped)
		case strings.HasPrefix(id, "OSV-"), strings.HasPrefix(id, "GHSA-"), strings.HasPrefix(id, "DEBIAN-"), strings.HasPrefix(id, "ALPINE-"), strings.EqualFold(f.Record.Source, "osv"):
			add("https://osv.dev/vulnerability/" + escaped)
		}
		source := strings.ToLower(f.Record.Source)
		if strings.Contains(source, "debian") {
			add("https://security-tracker.debian.org/tracker/" + escaped)
		}
		if strings.Contains(source, "alpine") && strings.HasPrefix(id, "CVE-") {
			add("https://security.alpinelinux.org/vuln/" + escaped)
		}
	}
	for _, ref := range f.Record.References {
		u, err := url.Parse(ref)
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			add(u.String())
		}
	}
	return out
}
