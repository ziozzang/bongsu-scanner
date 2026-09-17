package vulndb

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultNVDBaseURL = "https://nvd.nist.gov/feeds/json/cve/2.0"
const nvdMaxExpandedBytes int64 = 1 << 30

// NVDOptions configures the opt-in NVD source passed to Update. Keeping this
// separate leaves existing Options callers and source plugins unchanged.
type NVDOptions struct {
	// Years accepts a range or comma-separated list, e.g. "2024-2026" or
	// "2024,2026". Empty selects the current UTC year and previous two years.
	Years string
	// BaseURL overrides the official feed directory for internal mirrors.
	BaseURL string
}

type nvdSource struct{ options NVDOptions }

func (nvdSource) Name() string { return SourceNVD }

func parseNVDYears(spec string, now time.Time) ([]int, error) {
	current := now.UTC().Year()
	if strings.TrimSpace(spec) == "" {
		return []int{current - 2, current - 1, current}, nil
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid NVD years %q", spec)
		}
		first, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid NVD years %q", spec)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid NVD years %q", spec)
			}
		}
		if first < 2002 || last > current || first > last {
			return nil, fmt.Errorf("NVD years must be between 2002 and %d: %q", current, spec)
		}
		for year := first; year <= last; year++ {
			seen[year] = true
		}
	}
	years := make([]int, 0, len(seen))
	for year := range seen {
		years = append(years, year)
	}
	sort.Ints(years)
	return years, nil
}

func (s nvdSource) Feeds(opts *Options) ([]Feed, error) {
	years, err := parseNVDYears(s.options.Years, time.Now())
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(s.options.BaseURL), "/")
	if base == "" {
		base = DefaultNVDBaseURL
	}
	maxBytes := opts.MaxFeedBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFeedBytes
	}
	keys := make([]string, 0, len(years)+1)
	for _, year := range years {
		keys = append(keys, strconv.Itoa(year))
	}
	keys = append(keys, "modified")
	feeds := make([]Feed, 0, len(keys))
	for _, key := range keys {
		file := "nvdcve-2.0-" + key + ".json.gz"
		// A separate cache key invalidates the earlier severity-only conversion
		// without changing conversion semantics for other feeds.
		feeds = append(feeds, Feed{Source: SourceNVD, Key: key + "-cpe-v1", File: file, URL: base + "/" + file, MaxBytes: maxBytes,
			Parse: func(ctx context.Context, path string, _ int64, emit Emit, progress func(string)) error {
				return parseNVDFeed(ctx, path, emit, nvdMaxExpandedBytes, progress)
			},
		})
	}
	return feeds, nil
}

type nvdMetric struct {
	Type string `json:"type"`
	Data struct {
		Vector string `json:"vectorString"`
	} `json:"cvssData"`
}
type nvdCPEMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	Matches  []nvdCPEMatch `json:"cpeMatch"`
	Nodes    []nvdNode     `json:"nodes"`
	Children []nvdNode     `json:"children"`
}
type nvdCVE struct {
	Configurations []nvdNode `json:"configurations"`
	ID             string    `json:"id"`
	Published      string    `json:"published"`
	Modified       string    `json:"lastModified"`
	Descriptions   []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func convertNVD(v nvdCVE) *Record {
	r := &Record{ID: v.ID, Published: nvdTimestamp(v.Published), Modified: nvdTimestamp(v.Modified), Source: SourceNVD}
	for _, description := range v.Descriptions {
		if description.Lang == "en" {
			r.Summary = truncateText(description.Value, 1<<10)
			break
		}
	}
	for _, metrics := range []struct {
		typ     string
		entries []nvdMetric
	}{
		{"CVSS_V4", v.Metrics.V40}, {"CVSS_V3", v.Metrics.V31}, {"CVSS_V3", v.Metrics.V30}, {"CVSS_V2", v.Metrics.V2},
	} {
		if len(metrics.entries) == 0 {
			continue
		}
		chosen := metrics.entries[0]
		for _, entry := range metrics.entries {
			if entry.Type == "Primary" {
				chosen = entry
				break
			}
		}
		if strings.TrimSpace(chosen.Data.Vector) != "" {
			r.Severity = append(r.Severity, Severity{Type: metrics.typ, Score: chosen.Data.Vector})
		}
	}
	if len(r.Severity) > 0 {
		r.Database = map[string]any{"severity_source": "nvd"}
	}
	for _, ref := range v.References {
		if len(r.References) == 5 {
			break
		}
		if ref.URL != "" {
			r.References = append(r.References, Reference{Type: "WEB", URL: ref.URL})
		}
	}
	for _, config := range v.Configurations {
		appendNVDCPE(r, config, false, false, true)
	}
	return r
}

// NVD dates without a zone are UTC. Normalize them for chronological merging.
func nvdTimestamp(value string) string {
	if at, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return at.UTC().Format(time.RFC3339Nano)
	}
	if at, err := time.Parse("2006-01-02T15:04:05", value); err == nil {
		return at.UTC().Format(time.RFC3339Nano)
	}
	return value
}

func parseNVDFeed(ctx context.Context, path string, emit Emit, maxExpanded int64, progress ...func(string)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("NVD gzip: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: contextReader{ctx: ctx, r: gz}, N: maxExpanded + 1}
	dec := json.NewDecoder(limited)
	expect := func(want json.Delim) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if tok != want {
			return fmt.Errorf("NVD: expected %q", want)
		}
		return nil
	}
	if err := expect('{'); err != nil {
		return err
	}
	found := false
	requiresAND := 0
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := dec.Token()
		if err != nil {
			return err
		}
		if key != "vulnerabilities" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return err
			}
			continue
		}
		if found {
			return errors.New("NVD: duplicate vulnerabilities array")
		}
		found = true
		if err := expect('['); err != nil {
			return err
		}
		for dec.More() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var item struct {
				CVE nvdCVE `json:"cve"`
			}
			if err := dec.Decode(&item); err != nil {
				return err
			}
			if limited.N <= 0 {
				return errors.New("NVD expanded feed exceeds size limit")
			}
			if !strings.HasPrefix(item.CVE.ID, "CVE-") || !validID(item.CVE.ID) {
				return errors.New("NVD: invalid CVE ID")
			}
			record := convertNVD(item.CVE)
			for _, a := range record.Affected {
				if a.Database["requires_and"] == true {
					requiresAND++
				}
			}
			if err := emit(record); err != nil {
				return err
			}
		}
		if err := expect(']'); err != nil {
			return err
		}
	}
	if err := expect('}'); err != nil {
		return err
	}
	if !found {
		return errors.New("NVD: missing vulnerabilities array")
	}
	var extra json.RawMessage
	err = dec.Decode(&extra) // Read to EOF to verify the gzip checksum as well.
	if limited.N <= 0 {
		return errors.New("NVD expanded feed exceeds size limit")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("NVD: trailing JSON")
		}
		return err
	}
	if len(progress) > 0 && progress[0] != nil {
		progress[0](fmt.Sprintf("[db:nvd] CPE entries requiring AND (not matched): %d", requiresAND))
	}
	return ctx.Err()
}

// CPEAttributes splits a formatted CPE without treating escaped colons as separators.
// Short inventory CPEs may omit trailing ANY attributes; NVD supplies all eleven.
func CPEAttributes(raw string) ([]string, bool) {
	if !strings.HasPrefix(raw, "cpe:2.3:") {
		return nil, false
	}
	var parts []string
	start := 8
	for i := start; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			if i >= len(raw) {
				return nil, false
			}
			continue
		}
		if raw[i] == ':' {
			parts = append(parts, raw[start:i])
			start = i + 1
		}
	}
	parts = append(parts, raw[start:])
	if len(parts) < 4 || len(parts) > 11 {
		return nil, false
	}
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, " \t\r\n") {
			return nil, false
		}
	}
	for len(parts) < 11 {
		parts = append(parts, "*")
	}
	if parts[0] != "a" && parts[0] != "o" && parts[0] != "h" {
		return nil, false
	}
	return parts, true
}

func appendNVDCPE(r *Record, node nvdNode, requiresAND, negated, configuration bool) {
	requiresAND = requiresAND || node.Operator == "AND"
	negated = negated || node.Negate
	// Missing configuration operators wrap an OR node list in the NVD 2.0 feed.
	unsupported := node.Operator != "OR" && !(configuration && node.Operator == "")
	for _, m := range node.Matches {
		if !m.Vulnerable {
			continue
		}
		attrs, ok := CPEAttributes(m.Criteria)
		if !ok {
			continue
		}
		a := Affected{Ecosystem: "CPE", Package: attrs[1] + ":" + attrs[2], Database: map[string]any{
			"cpe": m.Criteria, "operator": node.Operator, "negate": negated, "node_children": len(node.Children) > 0 || len(node.Nodes) > 0,
		}}
		if requiresAND || unsupported {
			a.Database["requires_and"] = true
		}
		if m.StartExcluding != "" {
			a.Database["versionStartExcluding"] = m.StartExcluding
		}
		bounded := m.StartIncluding != "" || m.StartExcluding != "" || m.EndIncluding != "" || m.EndExcluding != ""
		if bounded {
			start := m.StartIncluding
			if start == "" {
				start = m.StartExcluding
			}
			if start == "" {
				start = "0"
			}
			events := []Event{{Introduced: start}}
			if m.EndExcluding != "" {
				events = append(events, Event{Fixed: m.EndExcluding})
			}
			if m.EndIncluding != "" {
				events = append(events, Event{LastAffected: m.EndIncluding})
			}
			a.Ranges = []Range{{Type: "ECOSYSTEM", Events: events}}
		} else if attrs[3] != "-" && !strings.ContainsAny(attrs[3], "*?") {
			a.Versions = []string{attrs[3]}
		} else if attrs[3] == "*" {
			a.Ranges = []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}
		}
		r.Affected = append(r.Affected, a)
	}
	for _, child := range node.Nodes {
		appendNVDCPE(r, child, requiresAND || unsupported, negated, false)
	}
	for _, child := range node.Children {
		appendNVDCPE(r, child, requiresAND || unsupported, negated, false)
	}
}
