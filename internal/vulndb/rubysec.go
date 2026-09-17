package vulndb

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/version"
)

const (
	SourceRubysec                 = "rubysec"
	DefaultRubysecURL             = "https://github.com/rubysec/ruby-advisory-db/archive/refs/heads/master.zip"
	RubysecMaxBytes         int64 = 64 << 20
	rubysecMemberMaxBytes         = 1 << 20
	rubysecMaxExpandedBytes       = 256 << 20
	rubysecMaxEntries             = 50000
)

type rubysecSource struct{}

func (rubysecSource) Name() string { return SourceRubysec }

func (rubysecSource) Feeds(opts *Options) ([]Feed, error) {
	max := RubysecMaxBytes
	if opts.MaxFeedBytes > 0 && opts.MaxFeedBytes < max {
		max = opts.MaxFeedBytes
	}
	return []Feed{{Source: SourceRubysec, Key: "ruby-advisory-db", URL: DefaultRubysecURL,
		File: "ruby-advisory-db-master.zip", Ecosystems: []string{"RubyGems"}, MaxBytes: max,
		Parse: func(ctx context.Context, p string, _ int64, emit Emit, _ func(string)) error {
			return parseRubysecZip(ctx, p, emit)
		},
	}}, nil
}

func parseRubysecZip(ctx context.Context, filename string, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	zr, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > rubysecMaxEntries {
		return fmt.Errorf("rubysec archive exceeds %d entries", rubysecMaxEntries)
	}
	var expanded uint64
	for _, f := range zr.File {
		if f.UncompressedSize64 > rubysecMaxExpandedBytes-expanded {
			return fmt.Errorf("rubysec archive exceeds %d expanded bytes", rubysecMaxExpandedBytes)
		}
		expanded += f.UncompressedSize64
	}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		parts := strings.Split(f.Name, "/")
		if len(parts) == 4 { // GitHub archives have one repository root directory.
			parts = parts[1:]
		}
		if len(parts) != 3 || parts[0] != "gems" || parts[1] == "" || parts[1] == "." || parts[1] == ".." || !strings.HasSuffix(parts[2], ".yml") {
			continue
		}
		if f.UncompressedSize64 > rubysecMemberMaxBytes {
			return fmt.Errorf("rubysec member %q exceeds size limit", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		// Read through EOF to verify the ZIP checksum; never extract paths.
		data, readErr := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, r: rc}, rubysecMemberMaxBytes+1))
		closeErr := rc.Close()
		if readErr != nil {
			return fmt.Errorf("rubysec %q: %w", f.Name, readErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if len(data) > rubysecMemberMaxBytes {
			return fmt.Errorf("rubysec member %q exceeds size limit", f.Name)
		}
		fields, err := readRubysecYAML(string(data))
		if err != nil {
			return fmt.Errorf("rubysec %q: %w", f.Name, err)
		}
		r, err := rubysecRecord(parts[1], strings.TrimSuffix(path.Base(f.Name), ".yml"), fields)
		if err != nil {
			return fmt.Errorf("rubysec %q: %w", f.Name, err)
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

// readRubysecYAML reads only the feed's scalar/list subset. It does not
// resolve tags, aliases or anchors. Unknown metadata is ignored; unsupported
// requirement expressions remain intact for the conservative range fallback.
// related also accepts the upstream related: {url: [items]} block layout.
func readRubysecYAML(data string) (map[string][]string, error) {
	lines := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	out := map[string][]string{}
	for i := 0; i < len(lines); {
		line := lines[i]
		i++
		trim := strings.TrimSpace(line)
		if trim == "" || trim == "---" || trim == "..." || strings.HasPrefix(trim, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("unsupported YAML at line %d", i)
		}
		start := i
		for i < len(lines) {
			s := lines[i]
			if s != "" && s[0] != ' ' && s[0] != '\t' && !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "#") {
				break
			}
			i++
		}
		switch key {
		case "gem", "cve", "ghsa", "osvdb", "title", "description", "date", "url", "related", "cvss_v3", "cvss_v4", "patched_versions", "unaffected_versions":
		default:
			continue
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate YAML key %q", key)
		}
		value = strings.TrimSpace(value)
		if value == "|" || value == ">" || value == "|-" || value == ">-" || value == "|+" || value == ">+" {
			out[key] = []string{rubysecBlock(lines[start:i], value)}
			continue
		}
		isList := key == "patched_versions" || key == "unaffected_versions" || key == "related" || strings.HasPrefix(key, "cvss_")
		if isList {
			out[key] = nil
			if value != "" && value != "[]" {
				s, err := rubysecScalar(value)
				if err != nil {
					return nil, err
				}
				out[key] = append(out[key], s)
			}
			for _, line := range lines[start:i] {
				s := strings.TrimSpace(line)
				if s == "" || strings.HasPrefix(s, "#") {
					continue
				}
				if key == "related" && strings.HasSuffix(s, ":") {
					continue
				}
				if !strings.HasPrefix(s, "- ") {
					return nil, fmt.Errorf("unsupported YAML list in %q", key)
				}
				s, err := rubysecScalar(strings.TrimSpace(s[2:]))
				if err != nil {
					return nil, err
				}
				out[key] = append(out[key], s)
			}
		} else {
			for _, continuation := range lines[start:i] {
				s := strings.TrimSpace(continuation)
				if s != "" && !strings.HasPrefix(s, "#") {
					value += " " + s
				}
			}
			s, err := rubysecScalar(value)
			if err != nil {
				return nil, err
			}
			out[key] = []string{s}
		}
	}
	return out, nil
}

func rubysecScalar(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "~" {
		return "", nil
	}
	if s[0] == '\'' || s[0] == '"' {
		quote := s[0]
		for i := 1; i < len(s); i++ {
			if quote == '"' && s[i] == '\\' {
				i++
				continue
			}
			if s[i] != quote {
				continue
			}
			if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			rest := strings.TrimSpace(s[i+1:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				break
			}
			if quote == '\'' {
				return strings.ReplaceAll(s[1:i], "''", "'"), nil
			}
			return strconv.Unquote(s[:i+1])
		}
		return "", fmt.Errorf("invalid quoted YAML scalar")
	}
	if strings.ContainsAny(s[:1], "&*!{[") {
		return "", fmt.Errorf("unsupported YAML scalar")
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s, nil
}

func rubysecBlock(lines []string, style string) string {
	indent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			n := len(line) - len(strings.TrimLeft(line, " "))
			if indent < 0 || n < indent {
				indent = n
			}
		}
	}
	var b strings.Builder
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			line = ""
		} else if indent >= 0 && len(line) >= indent {
			line = line[indent:]
		}
		b.WriteString(line)
		separator := "\n"
		if style[0] == '>' && i+1 < len(lines) && line != "" && !strings.HasPrefix(line, " ") {
			next := lines[i+1]
			if len(next) > indent && next[indent] != ' ' {
				separator = " "
			}
			if strings.TrimSpace(next) == "" {
				separator = ""
			}
		}
		b.WriteString(separator)
	}
	s := b.String()
	if strings.HasSuffix(style, "+") {
		return s
	}
	s = strings.TrimRight(s, "\n")
	if s != "" && !strings.HasSuffix(style, "-") {
		s += "\n"
	}
	return s
}

func rubysecRecord(gem, file string, fields map[string][]string) (*Record, error) {
	first := func(key string) string {
		if len(fields[key]) > 0 {
			return fields[key][0]
		}
		return ""
	}
	if declared := first("gem"); declared != "" && declared != gem {
		return nil, fmt.Errorf("gem does not match archive path")
	}
	r := &Record{Source: SourceRubysec, Summary: first("title"), Details: truncateDetails(first("description")), DetailsTruncated: len(first("description")) > MaxDetails}
	for _, spec := range [][2]string{{"cve", "CVE-"}, {"ghsa", "GHSA-"}, {"osvdb", "OSVDB-"}} {
		if id := first(spec[0]); id != "" {
			if !strings.HasPrefix(strings.ToUpper(id), spec[1]) {
				id = spec[1] + id
			} else {
				id = spec[1] + id[len(spec[1]):]
			}
			if !validID(id) {
				return nil, fmt.Errorf("invalid %s identifier", spec[0])
			}
			r.Aliases = append(r.Aliases, id)
			if r.ID == "" && spec[0] != "osvdb" {
				r.ID = id
			}
		}
	}
	if r.ID == "" {
		r.ID = "RUBYSEC-" + gem + "-" + file
	}
	if date := first("date"); date != "" {
		r.Published = date
		if t, err := time.Parse("2006-01-02", date); err == nil {
			r.Published = t.Format(time.RFC3339)
		}
	}
	for _, key := range []string{"cvss_v3", "cvss_v4"} {
		for _, score := range fields[key] {
			prefix := "CVSS:3."
			if key == "cvss_v4" {
				prefix = "CVSS:4."
			}
			if strings.HasPrefix(score, prefix) {
				r.Severity = append(r.Severity, Severity{Type: strings.ToUpper(key), Score: score})
			}
		}
	}
	for _, url := range dedupeStrings(append([]string{first("url")}, fields["related"]...)) {
		if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
			r.References = append(r.References, Reference{Type: "ADVISORY", URL: url})
		}
	}
	a := Affected{Ecosystem: "RubyGems", Package: gem}
	ranges, unmapped := rubysecRanges(fields["patched_versions"], fields["unaffected_versions"])
	a.Ranges = ranges
	if unmapped != "" {
		a.Database = map[string]any{"rubysec_unmapped": unmapped}
	}
	r.Affected = []Affected{a}
	return r, nil
}

var rubysecRequirement = regexp.MustCompile(`^(>=|~>|<)\s*([0-9]+(?:\.[0-9]+){0,3})$`)

// Mapping is intentionally limited to numeric releases: unaffected < X raises
// the lower bound; patched >= X closes the final range; patched ~> A.B.C
// closes [A.B.0,A.B.C) and excludes [A.B.C,A.(B+1).0) from later ranges.
// Branch ranges start at their own minor release (or the unaffected bound).
// The final >= range starts after the last earlier patched branch. Duplicate
// branch fixes use the earliest fix. Any unsupported requirement discards ALL
// ranges, leaving a versions-less entry for the matcher's no-usable-range result.
func rubysecRanges(patched, unaffected []string) ([]Range, string) {
	lower, final := "0", ""
	type branch struct{ start, fixed, end string }
	branches := map[string]branch{}
	var unmapped []string
	for _, req := range unaffected {
		m := rubysecRequirement.FindStringSubmatch(req)
		if m == nil || m[1] != "<" {
			unmapped = append(unmapped, req)
			continue
		}
		if rubysecCompare(m[2], lower) > 0 {
			lower = m[2]
		}
	}
	for _, req := range patched {
		m := rubysecRequirement.FindStringSubmatch(req)
		if m == nil {
			unmapped = append(unmapped, req)
			continue
		}
		switch m[1] {
		case ">=":
			if final == "" || rubysecCompare(m[2], final) < 0 {
				final = m[2]
			}
		case "~>":
			parts := strings.Split(m[2], ".")
			if len(parts) != 3 {
				unmapped = append(unmapped, req)
				continue
			}
			minor, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				unmapped = append(unmapped, req)
				continue
			}
			start := version.Normalize("RubyGems", parts[0]+"."+parts[1]+".0")
			b := branch{start: start, fixed: m[2], end: parts[0] + "." + strconv.FormatUint(minor+1, 10) + ".0"}
			if prev, ok := branches[start]; !ok || rubysecCompare(b.fixed, prev.fixed) < 0 {
				branches[start] = b
			}
		default:
			unmapped = append(unmapped, req)
		}
	}
	if len(unmapped) > 0 {
		for i, req := range unmapped {
			if req == "" {
				unmapped[i] = "empty requirement"
			}
		}
		return nil, strings.Join(unmapped, "; ")
	}
	if len(patched) == 0 {
		return nil, "missing patched_versions"
	}
	var ordered []branch
	for _, b := range branches {
		ordered = append(ordered, b)
	}
	sort.Slice(ordered, func(i, j int) bool { return rubysecCompare(ordered[i].start, ordered[j].start) < 0 })
	var ranges []Range
	add := func(start, fixed string) {
		if rubysecCompare(start, lower) < 0 {
			start = lower
		}
		if rubysecCompare(start, fixed) < 0 {
			ranges = append(ranges, Range{Type: "ECOSYSTEM", Events: []Event{{Introduced: start}, {Fixed: fixed}}})
		}
	}
	start := lower
	for _, b := range ordered {
		fixed := b.fixed
		if final != "" && rubysecCompare(final, fixed) < 0 {
			fixed = final
		}
		add(b.start, fixed)
		if (final == "" || rubysecCompare(b.fixed, final) < 0) && rubysecCompare(b.end, start) > 0 {
			start = b.end
		}
	}
	if final != "" {
		add(start, final)
	}
	return ranges, ""
}

func rubysecCompare(a, b string) int {
	n, _ := version.Compare("RubyGems", a, b) // only validated numeric releases
	return n
}
