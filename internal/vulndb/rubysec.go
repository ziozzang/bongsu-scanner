package vulndb

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"math/big"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/version"
)

const (
	SourceRubysec                 = "rubysec"
	DefaultRubysecURL             = "https://github.com/rubysec/ruby-advisory-db/archive/refs/heads/master.zip"
	RubysecMaxBytes         int64 = 64 << 20
	rubysecMemberMaxBytes         = 1 << 20
	rubysecMaxExpandedBytes       = 256 << 20
	rubysecMaxEntries             = 50000
	rubysecScalarMaxBytes         = 256 << 10
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
		Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
			unmapped := 0
			err := parseRubysecZip(ctx, p, func(r *Record) error {
				for _, a := range r.Affected {
					if constraints, ok := a.Database["rubysec_unmapped"].([]string); ok {
						unmapped += len(constraints)
					}
				}
				return emit(r)
			})
			if err == nil && unmapped > 0 && progress != nil {
				progress(fmt.Sprintf("[db:rubysec] warning: %d unmapped requirement entries", unmapped))
			}
			return err
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
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = zr.Close()
	}()
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
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
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
		case "gem", "cve", "ghsa", "osvdb", "title", "description", "date", "url", "related", "cvss_v2", "cvss_v3", "cvss_v4", "patched_versions", "unaffected_versions":
		default:
			continue
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate YAML key %q", key)
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
			style, _, _ := strings.Cut(value, " #")
			style = strings.TrimSpace(style)
			if !rubysecBlockHeader.MatchString(style) {
				return nil, fmt.Errorf("invalid YAML block header %q", value)
			}
			block, err := rubysecBlock(lines[start:i], style)
			if err != nil {
				return nil, err
			}
			out[key] = []string{block}
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
			var b strings.Builder
			if len(value) > rubysecScalarMaxBytes {
				return nil, rubysecScalarTooLarge()
			}
			b.WriteString(value)
			for _, continuation := range lines[start:i] {
				s := strings.TrimSpace(continuation)
				if s != "" && !strings.HasPrefix(s, "#") {
					if b.Len()+1+len(s) > rubysecScalarMaxBytes {
						return nil, rubysecScalarTooLarge()
					}
					b.WriteByte(' ')
					b.WriteString(s)
				}
			}
			value = b.String()
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
	if len(s) > rubysecScalarMaxBytes {
		return "", rubysecScalarTooLarge()
	}
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
			return rubysecUnquote(s[1:i])
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

func rubysecScalarTooLarge() error {
	return fmt.Errorf("YAML scalar exceeds %d bytes", rubysecScalarMaxBytes)
}

// YAML escapes differ from Go escapes: notably \xNN denotes a code point.
func rubysecUnquote(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", fmt.Errorf("incomplete YAML escape")
		}
		escapes := map[byte]rune{'0': 0, 'a': '\a', 'b': '\b', 't': '\t', 'n': '\n', 'v': '\v', 'f': '\f', 'r': '\r', 'e': 0x1b, ' ': ' ', '"': '"', '/': '/', '\\': '\\', 'N': 0x85, '_': 0xa0, 'L': 0x2028, 'P': 0x2029}
		if r, ok := escapes[s[i]]; ok {
			b.WriteRune(r)
			continue
		}
		n := 0
		switch s[i] {
		case 'x':
			n = 2
		case 'u':
			n = 4
		case 'U':
			n = 8
		default:
			return "", fmt.Errorf("unknown YAML escape \\%c", s[i])
		}
		if i+n >= len(s) {
			return "", fmt.Errorf("incomplete YAML Unicode escape")
		}
		r, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(r)) { // #nosec G115 -- ParseUint is limited to 32 bits; ValidRune rejects wrapped negatives and values above MaxRune.
			return "", fmt.Errorf("invalid YAML Unicode escape")
		}
		b.WriteRune(rune(r)) // #nosec G115 -- ParseUint is limited to 32 bits; ValidRune rejects wrapped negatives and values above MaxRune.
		i += n
	}
	return b.String(), nil
}

var rubysecBlockHeader = regexp.MustCompile(`^[|>](?:[1-9][+-]?|[+-][1-9]?)?$`)

func rubysecBlock(lines []string, style string) (string, error) {
	indent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			n := len(line) - len(strings.TrimLeft(line, " "))
			if indent < 0 || n < indent {
				indent = n
			}
		}
	}
	for _, c := range style[1:] {
		if c >= '1' && c <= '9' {
			indent = int(c - '0')
			break
		}
	}
	var b strings.Builder
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			line = ""
		} else if indent >= 0 {
			if len(line)-len(strings.TrimLeft(line, " ")) < indent {
				return "", fmt.Errorf("invalid YAML block indentation")
			}
			line = line[indent:]
		}
		if b.Len()+len(line)+1 > rubysecScalarMaxBytes {
			return "", rubysecScalarTooLarge()
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
	if strings.Contains(style, "+") {
		return s, nil
	}
	s = strings.TrimRight(s, "\n")
	if s != "" && !strings.Contains(style, "-") {
		s += "\n"
	}
	return s, nil
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
	for _, key := range []string{"cvss_v2", "cvss_v3", "cvss_v4"} {
		for _, score := range fields[key] {
			prefix := "CVSS:3."
			if key == "cvss_v4" {
				prefix = "CVSS:4."
			}
			n, err := strconv.ParseFloat(score, 64)
			numeric := err == nil && n >= 0 && n <= 10
			vectorV2 := key == "cvss_v2" && (strings.HasPrefix(score, "AV:") || strings.HasPrefix(score, "CVSS:2.0/"))
			if numeric || vectorV2 || key != "cvss_v2" && strings.HasPrefix(score, prefix) {
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
	if len(unmapped) > 0 {
		a.Database = map[string]any{"rubysec_unmapped": unmapped}
	}
	r.Affected = []Affected{a}
	return r, nil
}

var rubysecRequirement = regexp.MustCompile(`^(>=|<=|~>|!=|=|>|<)?\s*([0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9a-zA-Z]+(?:\.[0-9a-zA-Z]+)*)?)$`)
var rubysecVersionTokens = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

// Intervals are half open; an empty end means infinity. Each requirement
// string is an intersection, list entries are a union, and vulnerable versions
// are the complement of patched OR unaffected (bundler-audit's predicate).
type rubysecInterval struct{ lo, hi string }

func rubysecRanges(patched, unaffected []string) ([]Range, []string) {
	var safe []rubysecInterval
	var unmapped []string
	for _, list := range [][]string{patched, unaffected} {
		for _, req := range list {
			intervals, ok := rubysecRequirementIntervals(req)
			if !ok {
				if req == "" {
					req = "empty requirement"
				}
				unmapped = append(unmapped, req)
				continue
			}
			safe = append(safe, intervals...)
		}
	}
	sort.Slice(safe, func(i, j int) bool { return rubysecCompare(safe[i].lo, safe[j].lo) < 0 })
	var ranges []Range
	start := "0"
	add := func(lo, hi string) {
		events := []Event{{Introduced: lo}}
		if hi != "" {
			events = append(events, Event{Fixed: hi})
		}
		ranges = append(ranges, Range{Type: "ECOSYSTEM", Events: events})
	}
	for _, interval := range safe {
		if rubysecCompare(start, interval.lo) < 0 {
			add(start, interval.lo)
		}
		if interval.hi == "" {
			return ranges, unmapped
		}
		if rubysecCompare(start, interval.hi) < 0 {
			start = interval.hi
		}
	}
	add(start, "")
	return ranges, unmapped
}

func rubysecRequirementIntervals(req string) ([]rubysecInterval, bool) {
	intervals := []rubysecInterval{{"0", ""}}
	for _, constraint := range strings.Split(req, ",") {
		m := rubysecRequirement.FindStringSubmatch(strings.TrimSpace(constraint))
		if m == nil {
			return nil, false
		}
		v, core, exact, ok := rubysecVersionBoundary(m[2])
		if !ok {
			return nil, false
		}
		var operand []rubysecInterval
		switch m[1] {
		case ">=":
			operand = []rubysecInterval{{v, ""}}
		case "<":
			operand = []rubysecInterval{{"0", v}}
		case "", "=":
			if exact {
				operand = []rubysecInterval{{v, rubysecAfter(v)}}
			}
		case "!=":
			operand = []rubysecInterval{{"0", ""}}
			if exact {
				operand = []rubysecInterval{{"0", v}, {rubysecAfter(v), ""}}
			}
		case ">":
			after := v
			if exact {
				after = rubysecAfter(v)
			}
			operand = []rubysecInterval{{after, ""}}
		case "<=":
			after := v
			if exact {
				after = rubysecAfter(v)
			}
			operand = []rubysecInterval{{"0", after}}
		case "~>":
			// Gem::Version#bump removes the last numeric segment, then increments
			// the preceding one. Its release comparison excludes upper prereleases.
			if len(core) > 1 {
				core = core[:len(core)-1]
			}
			core[len(core)-1] = rubysecIncrement(core[len(core)-1])
			upper, _ := rubysecCoreBoundary(core, []string{"0"})
			operand = []rubysecInterval{{v, upper}}
		}
		var intersection []rubysecInterval
		for _, a := range intervals {
			for _, b := range operand {
				lo, hi := a.lo, a.hi
				if rubysecCompare(b.lo, lo) > 0 {
					lo = b.lo
				}
				if hi == "" || b.hi != "" && rubysecCompare(b.hi, hi) < 0 {
					hi = b.hi
				}
				if hi == "" || rubysecCompare(lo, hi) < 0 {
					intersection = append(intersection, rubysecInterval{lo, hi})
				}
			}
		}
		intervals = intersection
	}
	return intervals, true
}

// Encode Ruby's dotted prereleases as explicit semver-like boundaries so the
// shared RubyGems comparator can order rc1 before rc2 and before the release.
func rubysecVersionBoundary(v string) (string, []string, bool, bool) {
	tokens := rubysecVersionTokens.FindAllString(v, -1)
	var core, pre []string
	prerelease := false
	for _, token := range tokens {
		if token[0] >= 'A' && token[0] <= 'Z' || token[0] >= 'a' && token[0] <= 'z' {
			prerelease = true
		}
		if prerelease {
			pre = append(pre, token)
		} else {
			core = append(core, token)
		}
	}
	if left, right, ok := strings.Cut(v, "-"); ok {
		core = strings.Split(left, ".")
		pre = rubysecVersionTokens.FindAllString(right, -1)
	}
	if len(core) == 0 {
		return "", nil, false, false
	}
	boundary, exact := rubysecCoreBoundary(core, pre)
	return boundary, core, exact, version.Valid("RubyGems", boundary)
}

// Project higher precision Ruby versions onto the shared comparator's domain.
// No representable version lies between A.B.C.D and A.B.C.(D+1)-0. Thus a
// nonzero fifth (or later) component falls at the latter cut; equality to that
// unrepresentable version is empty. Keep original precision for ~>'s bump.
// Installed versions outside this domain still require a RubyGems comparator
// in internal/version; emitting unsupported range endpoints would lose even
// matches for ordinary releases.
func rubysecCoreBoundary(core, pre []string) (string, bool) {
	exact := true
	if len(core) > 4 {
		for _, part := range core[4:] {
			if strings.TrimLeft(part, "0") != "" {
				exact = false
				break
			}
		}
		core = core[:4]
	}
	if !exact {
		return strings.Join(core[:3], ".") + "." + rubysecIncrement(core[3]) + "-0", false
	}
	boundary := strings.Join(core, ".")
	if len(pre) > 0 {
		boundary += "-" + strings.Join(pre, ".")
	}
	return boundary, true
}

func rubysecIncrement(s string) string {
	n, _ := new(big.Int).SetString(s, 10)
	return n.Add(n, big.NewInt(1)).String()
}

// OSV has inclusive introduced boundaries. In the shared comparator's domain
// (at most four numeric components), the next core's minimum prerelease is the
// boundary immediately above a release; appending .0 is the next prerelease.
func rubysecAfter(v string) string {
	if strings.Contains(v, "-") {
		return v + ".0"
	}
	parts := strings.Split(v, ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	parts[3] = rubysecIncrement(parts[3])
	return strings.Join(parts, ".") + "-0"
}

func rubysecCompare(a, b string) int {
	n, err := version.Compare("RubyGems", a, b)
	if err != nil {
		panic("invalid rubysec boundary: " + err.Error())
	}
	return n
}
