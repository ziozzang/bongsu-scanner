package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/version"
)

// Source names as stored in Record.Source and SourceMeta.Name.
const (
	SourceOSV    = "osv"
	SourceAlpine = "alpine-secdb"
	SourceDebian = "debian-tracker"
	SourceGHSA   = "ghsa"
	SourceNVD    = "nvd"
)

// Default upstream locations. Tests and internal mirrors override them via
// Options.
const (
	DefaultOSVBaseURL    = "https://osv-vulnerabilities.storage.googleapis.com"
	DefaultAlpineBaseURL = "https://secdb.alpinelinux.org"
	DefaultDebianURL     = "https://security-tracker.debian.org/tracker/data/json"
	DefaultGHSAURL       = "https://github.com/github/advisory-database/archive/refs/heads/main.zip"

	// DefaultMaxFeedBytes bounds one downloaded feed file (OSV zip, secdb
	// JSON, tracker JSON). The OSV Ubuntu and Chainguard exports exceed it;
	// raise Options.MaxFeedBytes to fetch them.
	DefaultMaxFeedBytes int64 = 512 << 20
	// GHSAMaxBytes bounds the GitHub advisory-database repository archive.
	GHSAMaxBytes int64 = 1 << 30

	// MaxDetails bounds Record.Details including the truncation marker.
	// Keep environmental prerequisites that often occur late in advisories.
	MaxDetails = 64 << 10
)

// DefaultOSVEcosystems is the OSV ecosystem list fetched when
// Options.Ecosystems is empty. Ubuntu and Chainguard exports exceed the
// default feed size bound; select them explicitly with a larger MaxFeedBytes.
var DefaultOSVEcosystems = []string{
	"Debian", "Alpine", "Wolfi",
	"npm", "PyPI", "Go", "crates.io", "Maven", "RubyGems", "NuGet", "Packagist",
}

// DefaultAlpineReleases is fetched when Options.AlpineReleases is empty.
var DefaultAlpineReleases = []string{"v3.18", "v3.19", "v3.20", "v3.21", "v3.22"}

// DefaultSources are fetched when Options.Sources is empty. GHSA and NVD
// are opt-in because their archives can be large; rubysec is small (a few
// MB) and fills gaps in OSV's RubyGems coverage, so it is on by default.
var DefaultSources = []string{SourceOSV, SourceAlpine, SourceDebian, "rubysec"}

// Emit receives one converted record. Parsers call it once per record and
// stop when it returns an error.
type Emit func(*Record) error

// Parser converts one downloaded feed file (already on disk) into records.
// size is the file length; progress receives human-readable status lines.
// Distinct feeds may be parsed concurrently; a feed is parsed once at a time.
type Parser func(ctx context.Context, path string, size int64, emit Emit, progress func(string)) error

// Feed is one downloadable file of a Source. Key is unique within the source
// and safe as a file name; File names the raw copy kept under raw/<source>/.
type Feed struct {
	Source     string
	Key        string
	URL        string
	File       string
	Ecosystems []string // ecosystems the feed is declared to cover
	MaxBytes   int64
	Parse      Parser
}

// Source is a plugin that knows which feed files to download for the given
// options and how to parse each of them. The update engine performs the
// conditional GET (If-None-Match / If-Modified-Since from the previous
// SourceMeta), keeps the raw file, runs Parse, and records the SourceMeta.
type Source interface {
	Name() string
	Feeds(opts *Options) ([]Feed, error)
}

// SourceFactory builds a Source; the registry maps names and aliases to it.
type SourceFactory func() Source

var registry = map[string]SourceFactory{
	SourceOSV:    func() Source { return &osvSource{} },
	"alpine":     func() Source { return &alpineSource{} },
	SourceAlpine: func() Source { return &alpineSource{} },
	"debian":     func() Source { return &debianSource{} },
	SourceDebian: func() Source { return &debianSource{} },
	SourceGHSA:   func() Source { return &ghsaSource{} },
	"github":     func() Source { return &ghsaSource{} },
	SourceNVD:    func() Source { return &nvdSource{} },
	"rubysec":    func() Source { return &rubysecSource{} },
}

// RegisterSource adds or replaces a source plugin under name.
func RegisterSource(name string, f SourceFactory) { registry[strings.ToLower(name)] = f }

// LookupSource resolves a source by name or alias ("alpine", "debian").
func LookupSource(name string) (Source, bool) {
	f, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, false
	}
	return f(), true
}

// SourceNames lists the canonical source names.
func SourceNames() []string {
	return []string{SourceOSV, SourceAlpine, SourceDebian, SourceGHSA, SourceNVD}
}

// CanonicalSource maps an alias to the canonical source name.
func CanonicalSource(name string) string {
	if s, ok := LookupSource(name); ok {
		return s.Name()
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// fetchResult is what fetchFeed reports back to the update engine.
type fetchResult struct {
	Meta        SourceMeta
	NotModified bool
}

// fetchFeed downloads feed.URL into rawPath (creating parent directories)
// while hashing the body. When prev has an ETag or Last-Modified, they are
// sent as conditional headers unless force is set; a 304 yields
// NotModified=true and prev is returned with its FetchedAt refreshed.
func fetchFeed(ctx context.Context, client *httpx.Client, feed Feed, prev *SourceMeta, rawPath string, force bool, now time.Time) (fetchResult, error) {
	meta := SourceMeta{Name: feed.Source, URL: feed.URL, Ecosystems: append([]string(nil), feed.Ecosystems...), FetchedAt: now}
	headers := map[string]string{}
	if prev != nil && !force {
		headers["If-None-Match"] = prev.ETag
		headers["If-Modified-Since"] = prev.LastMod
	}
	if err := os.MkdirAll(filepath.Dir(rawPath), 0o755); err != nil {
		return fetchResult{Meta: meta}, err
	}
	f, err := os.CreateTemp(filepath.Dir(rawPath), ".download-*")
	if err != nil {
		return fetchResult{Meta: meta}, err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, etag, lastMod, err := client.Download(ctx, feed.URL, headers, io.MultiWriter(f, h), feed.MaxBytes)
	closeErr := f.Close()
	if errors.Is(err, httpx.ErrNotModified) {
		if prev == nil {
			return fetchResult{Meta: meta}, errors.New("unexpected not-modified response without previous feed")
		}
		m := *prev
		m.FetchedAt = now
		m.Error = ""
		return fetchResult{Meta: m, NotModified: true}, nil
	}
	if err != nil {
		return fetchResult{Meta: meta}, err
	}
	if closeErr != nil {
		return fetchResult{Meta: meta}, closeErr
	}
	meta.ETag, meta.LastMod = etag, lastMod
	if err := os.Rename(f.Name(), rawPath); err != nil {
		return fetchResult{Meta: meta}, err
	}
	meta.Bytes = n
	meta.SHA256 = hex.EncodeToString(h.Sum(nil))
	return fetchResult{Meta: meta}, nil
}

// truncateDetails cuts s to MaxDetails bytes, including "...", on a rune boundary.
func truncateDetails(s string) string {
	return truncateText(s, MaxDetails)
}

func truncateText(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes - len("...")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// DetailsMayBeTruncated includes records written before the explicit flag was
// introduced. That writer kept up to 2048 UTF-8 bytes followed by "...";
// cutting a four-byte rune can make the final length as short as 2048 bytes.
// The legacy check is necessarily a heuristic, not proof of missing text.
func DetailsMayBeTruncated(r Record) bool {
	return r.DetailsTruncated || (len(r.Details) >= 2048 && len(r.Details) <= 2051 && strings.HasSuffix(r.Details, "..."))
}

// mergeDetails prefers a complete description, then the longest available
// text with the same completeness. A lexical tie-break makes merging stable
// regardless of source order without combining incompatible descriptions.
func mergeDetails(dst, src *Record) {
	if src.Details == "" {
		return
	}
	srcCut, dstCut := DetailsMayBeTruncated(*src), DetailsMayBeTruncated(*dst)
	prefer := dst.Details == "" || (dstCut && !srcCut)
	if srcCut == dstCut {
		prefer = prefer || len(src.Details) > len(dst.Details) || (len(src.Details) == len(dst.Details) && src.Details < dst.Details)
	}
	if prefer {
		dst.Details = src.Details
		dst.DetailsTruncated = src.DetailsTruncated
	}
}

// dedupeStrings returns the unique non-empty entries of in, preserving order.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// affectedKey identifies an Affected entry for de-duplication when records
// from several sources are merged.
func affectedKey(a Affected) string {
	b, _ := json.Marshal(struct {
		E string
		P string
		R []Range
		V []string
	}{a.Ecosystem, a.Package, a.Ranges, a.Versions})
	return string(b)
}

// Merge folds src into dst: affected entries, aliases, related IDs,
// references and severities are unioned; summary is kept from dst unless
// empty, and the fullest description is selected; Published is the earliest and Modified the latest
// timestamp; Source becomes a comma-joined list of provenance names.
func Merge(dst, src *Record) {
	for _, provenance := range src.Provenance {
		addProvenance(dst, provenance)
	}
	if len(src.Database) > 0 {
		if dst.Database == nil {
			dst.Database = map[string]any{}
		}
		for key, value := range src.Database {
			if key == "severity_source" && len(dst.Severity) > 0 {
				continue
			}
			if _, exists := dst.Database[key]; !exists {
				dst.Database[key] = value
			}
		}
	}
	if dst.ID == "" {
		dst.ID = src.ID
	}
	dst.Aliases = dedupeStrings(append(dst.Aliases, src.Aliases...))
	dst.Related = dedupeStrings(append(dst.Related, src.Related...))
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
	mergeDetails(dst, src)
	dst.Published = mergeRFC3339(dst.Published, src.Published, true)
	dst.Modified = mergeRFC3339(dst.Modified, src.Modified, false)
	if dst.Withdrawn == "" {
		dst.Withdrawn = src.Withdrawn
	}
	if len(src.Severity) > 0 {
		seen := make(map[Severity]struct{}, len(dst.Severity))
		for _, s := range dst.Severity {
			seen[s] = struct{}{}
		}
		for _, s := range src.Severity {
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				dst.Severity = append(dst.Severity, s)
			}
		}
	}
	if len(src.Affected) > 0 {
		seen := make(map[string]int, len(dst.Affected))
		for i, a := range dst.Affected {
			seen[affectedKey(a)] = i
		}
		for _, a := range src.Affected {
			k := affectedKey(a)
			if i, ok := seen[k]; ok {
				out := &dst.Affected[i]
				prefer := nativeAffectedSource(a.Ecosystem, src.Source)
				out.Database = mergeSpecificMaps(out.Database, a.Database, prefer)
				out.Specific = mergeSpecificMaps(out.Specific, a.Specific, prefer)
				if out.PURL == "" || (prefer && a.PURL != "") {
					out.PURL = a.PURL
				}
				for _, severity := range a.Severity {
					found := false
					for _, existing := range out.Severity {
						if existing == severity {
							found = true
							break
						}
					}
					if !found {
						out.Severity = append(out.Severity, severity)
					}
				}
			} else {
				seen[k] = len(dst.Affected)
				dst.Affected = append(dst.Affected, a)
			}
		}
	}
	if len(src.References) > 0 {
		seen := make(map[string]struct{}, len(dst.References))
		for _, r := range dst.References {
			seen[r.URL] = struct{}{}
		}
		for _, r := range src.References {
			if _, ok := seen[r.URL]; !ok {
				seen[r.URL] = struct{}{}
				dst.References = append(dst.References, r)
			}
		}
	}
	dst.Source = joinSources(dst.Source, src.Source)
}

func nativeAffectedSource(ecosystem, source string) bool {
	for _, name := range strings.Split(source, ",") {
		if BaseEcosystem(ecosystem) == "Debian" && name == SourceDebian || BaseEcosystem(ecosystem) == "Alpine" && name == SourceAlpine {
			return true
		}
	}
	return false
}

// Merge into a fresh map so merging a record cannot change the other source.
func mergeSpecificMaps(dst, src map[string]any, preferSrc bool) map[string]any {
	if len(src) == 0 {
		return dst
	}
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		old, exists := out[k]
		oldMap, oldOK := old.(map[string]any)
		newMap, newOK := v.(map[string]any)
		if oldOK && newOK {
			out[k] = mergeSpecificMaps(oldMap, newMap, preferSrc)
		} else if !exists || preferSrc {
			out[k] = v
		}
	}
	return out
}

// Keep errors.Is/As working while making nested external error text safe for
// terminal output (including errors returned by source plugins).
type terminalSafeError struct{ error }

func (e terminalSafeError) Error() string { return httpx.Sanitize(e.error.Error()) }
func (e terminalSafeError) Unwrap() error { return e.error }

// mergeRFC3339 selects a timestamp by instant, rather than by its textual
// representation. RFC 3339 permits offsets and variable fractional precision,
// neither of which have chronological lexical ordering. Valid input wins over
// malformed input; lexical ordering remains a deterministic fallback when both
// values are malformed or denote the same instant.
func mergeRFC3339(dst, src string, earliest bool) string {
	if dst == "" {
		return src
	}
	if src == "" {
		return dst
	}
	dstTime, dstErr := time.Parse(time.RFC3339Nano, dst)
	srcTime, srcErr := time.Parse(time.RFC3339Nano, src)
	if dstErr != nil || srcErr != nil {
		if dstErr == nil {
			return dst
		}
		if srcErr == nil {
			return src
		}
	} else if !dstTime.Equal(srcTime) {
		if dstTime.Before(srcTime) == earliest {
			return dst
		}
		return src
	}
	if (dst < src) == earliest {
		return dst
	}
	return src
}

func joinSources(a, b string) string {
	parts := dedupeStrings(append(strings.Split(a, ","), strings.Split(b, ",")...))
	return strings.Join(parts, ",")
}

// sortAffected orders affected entries deterministically.
func sortAffected(a []Affected) {
	sort.SliceStable(a, func(i, j int) bool {
		if a[i].Ecosystem != a[j].Ecosystem {
			return a[i].Ecosystem < a[j].Ecosystem
		}
		if a[i].Package != a[j].Package {
			return a[i].Package < a[j].Package
		}
		x, y := firstFixedVersion(a[i]), firstFixedVersion(a[j])
		if BaseEcosystem(a[i].Ecosystem) == "Alpine" {
			if c := version.CompareApk(x, y); c != 0 {
				return c < 0
			}
		}
		if x != y {
			return x < y
		}
		// Equal first fixes can still have different ranges or metadata.
		left, _ := json.Marshal(a[i])
		right, _ := json.Marshal(a[j])
		return string(left) < string(right)
	})
}

func firstFixedVersion(a Affected) string {
	for _, rg := range a.Ranges {
		for _, event := range rg.Events {
			if event.Fixed != "" {
				return event.Fixed
			}
		}
	}
	return ""
}

// idPattern accepts advisory identifiers such as CVE-2024-1234,
// GHSA-xxxx-xxxx-xxxx, ALPINE-13661, DW202402-001 or RLSA-2019:0975 (Rocky
// and AlmaLinux errata carry a colon): an alphabetic prefix, a dash, and a
// non-empty alphanumeric tail (underscores allowed, e.g. rubysec fallback
// ids) whose segments are joined by '-', ':', '.' or '_'.
// GHSA identifiers can contain letters only; requiring a digit silently
// discards valid advisories.
var idPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9_]+(?:[-:._][A-Za-z0-9_]+)*$`)

func validID(id string) bool { return len(id) <= 128 && idPattern.MatchString(id) }

// safeName makes s usable as a single path component.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "_"
	}
	return out
}

func formatCount(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// FormatCount and FormatBytes are exported for CLI output.
func FormatCount(n int) string   { return formatCount(n) }
func FormatBytes(n int64) string { return formatBytes(n) }

func addProvenance(r *Record, source RecordSource) {
	for _, existing := range r.Provenance {
		if existing == source {
			return
		}
	}
	r.Provenance = append(r.Provenance, source)
}
