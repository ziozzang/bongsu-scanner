package vulndb

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
)

// osvEntryMaxBytes bounds one JSON member inside an OSV/GHSA zip so a
// crafted archive cannot expand without limit.
const (
	osvEntryMaxBytes               = 64 << 20
	osvMaxEntries                  = 2_000_000
	osvMaxUncompressedBytes uint64 = uint64(DefaultMaxFeedUncompressedBytes)
	osvMaxSummary                  = 1 << 10
	osvMaxAliases                  = 100
	osvMaxReferences               = 100
)

// Injectable so aggregate version bounds can be exercised with small fixtures.
var osvMaxVersions = 5_000_000

// osvVuln is the subset of the OSV schema that is read from feeds.
type osvVuln struct {
	ID         string         `json:"id"`
	Modified   string         `json:"modified"`
	Published  string         `json:"published"`
	Withdrawn  string         `json:"withdrawn"`
	Aliases    []string       `json:"aliases"`
	Related    []string       `json:"related"`
	Upstream   []string       `json:"upstream"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Severity   []Severity     `json:"severity"`
	Affected   []osvAffected  `json:"affected"`
	References []Reference    `json:"references"`
	Database   map[string]any `json:"database_specific"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges   []osvRange     `json:"ranges"`
	Versions []string       `json:"versions"`
	Specific map[string]any `json:"ecosystem_specific"`
	Database map[string]any `json:"database_specific"`
	Severity []Severity     `json:"severity"`
}

type osvRange struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo"`
	Events []Event `json:"events"`
}

// droppedSpecificKeys are ecosystem_specific entries that are large and not
// needed for matching (Ubuntu lists every binary package build per release).
var droppedSpecificKeys = map[string]bool{"binaries": true}

// ConvertOSV turns a decoded OSV record into a Record with the given
// provenance. Details are truncated to MaxDetails; "upstream" identifiers
// (OSV 1.7) are folded into Aliases so distribution advisories group with
// their CVE.
func ConvertOSV(v *osvVuln, source string) (*Record, bool) {
	if !validID(v.ID) {
		return nil, false
	}
	r := &Record{
		ID:               v.ID,
		Aliases:          boundedOSVStrings(osvMaxAliases, 128, v.Aliases, v.Upstream),
		Related:          boundedOSVStrings(osvMaxAliases, 128, v.Related),
		Summary:          truncateText(v.Summary, osvMaxSummary),
		Details:          truncateDetails(v.Details),
		DetailsTruncated: len(v.Details) > MaxDetails,
		Published:        v.Published,
		Modified:         v.Modified,
		Withdrawn:        v.Withdrawn,
		Severity:         v.Severity,
		References:       boundedOSVReferences(v.References),
		Source:           source,
		Database:         v.Database,
	}
	for _, a := range v.Affected {
		eco := strings.TrimSpace(a.Package.Ecosystem)
		if strings.HasPrefix(eco, "Debian:") {
			eco = "Debian:" + NormalizeDebianRelease(EcosystemRelease(eco))
		}
		name := strings.TrimSpace(a.Package.Name)
		if eco == "" {
			continue
		}
		if raw := strings.TrimSpace(a.Package.PURL); raw != "" {
			if parsed, err := purl.Parse(raw); err == nil {
				purlEco := PURLTypeToEcosystem(parsed.Type, parsed.Namespace)
				if purlEco != "" && BaseEcosystem(purlEco) != BaseEcosystem(eco) {
					continue
				}
				if name == "" && purlEco != "" {
					name = parsed.FullName()
				}
			}
		}
		if name == "" {
			continue
		}
		out := Affected{Ecosystem: eco, Package: name, PURL: a.Package.PURL,
			Versions: boundedOSVVersions(a.Versions), Severity: a.Severity}
		for _, rg := range a.Ranges {
			if len(rg.Events) == 0 {
				continue
			}
			out.Ranges = append(out.Ranges, Range{Type: rg.Type, Repo: rg.Repo, Events: rg.Events})
		}
		if len(a.Specific) > 0 {
			for k := range droppedSpecificKeys {
				delete(a.Specific, k)
			}
			if len(a.Specific) > 0 {
				out.Specific = a.Specific
			}
		}
		if len(a.Database) > 0 {
			out.Database = a.Database
		}
		if BaseEcosystem(eco) == "Debian" {
			if urgency, ok := a.Specific["urgency"]; ok {
				// Explicit database metadata takes precedence over the OSV fallback.
				out.Database = mergeSpecificMaps(out.Database, map[string]any{"urgency": urgency}, false)
			}
		}
		r.Affected = append(r.Affected, out)
	}
	if len(r.Affected) == 0 {
		return nil, false
	}
	return r, true
}

// Copy only bounded strings into new slices; slicing the input would retain
// its entire backing array. Oversized identifiers/URLs are omitted, never
// truncated into different identifiers/URLs.
func boundedOSVStrings(maxCount, maxBytes int, lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range lists {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" || len(s) > maxBytes || seen[s] {
				continue
			}
			s = strings.Clone(s)
			seen[s] = true
			out = append(out, s)
			if len(out) == maxCount {
				return out
			}
		}
	}
	return out
}

func boundedOSVReferences(refs []Reference) []Reference {
	var out []Reference
	for _, ref := range refs {
		if len(ref.URL) > 2048 || len(ref.Type) > 128 {
			continue
		}
		out = append(out, ref)
		if len(out) == osvMaxReferences {
			break
		}
	}
	return out
}

func boundedOSVVersions(versions []string) []string {
	var out []string
	for _, v := range versions {
		if len(v) > 1024 {
			continue
		}
		out = append(out, strings.Clone(v))
	}
	return out
}

// parseOSVZip walks a zip of OSV JSON files. accept filters member names
// (nil accepts every *.json). Corrupt or oversized members fail the feed so
// an update cannot install a silently incomplete replacement database.
func parseOSVZip(ctx context.Context, zipPath string, source string, accept func(name string) bool, emit Emit, progress func(string)) (int, error) {
	return parseOSVZipBounded(ctx, zipPath, source, accept, emit, progress, osvMaxEntries, osvMaxUncompressedBytes)
}

func parseOSVZipBounded(ctx context.Context, zipPath string, source string, accept func(name string) bool, emit Emit, progress func(string), maxEntries int, maxBytes uint64) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > maxEntries {
		return 0, fmt.Errorf("OSV zip exceeds %d entries", maxEntries)
	}
	// Preflight every member, including filtered members, before emitting any
	// records. ZIP reads below verify these declared sizes and CRCs through EOF.
	var expanded uint64
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if f.UncompressedSize64 > maxBytes-expanded {
			return 0, fmt.Errorf("OSV zip exceeds %d total uncompressed bytes; increase --max-feed-uncompressed BYTES", maxBytes)
		}
		expanded += f.UncompressedSize64
	}
	var count int
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		name := f.Name
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if accept != nil && !accept(name) {
			continue
		}
		if f.UncompressedSize64 > osvEntryMaxBytes {
			return count, fmt.Errorf("%q: OSV member exceeds %d bytes", path.Base(name), osvEntryMaxBytes)
		}
		rec, err := decodeOSVMember(f, source)
		if err != nil {
			return count, fmt.Errorf("%q: %w", path.Base(name), terminalSafeError{err})
		}
		if rec == nil {
			continue
		}
		if err := emit(rec); err != nil {
			return count, err
		}
		count++
		if progress != nil && count%20000 == 0 {
			progress(fmt.Sprintf("%s records parsed", formatCount(count)))
		}
	}
	return count, nil
}

func decodeOSVMember(f *zip.File, source string) (*Record, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Reading through EOF checks ZIP CRC/size errors; decoding just the first
	// object can miss both corruption after the object and trailing JSON.
	// The checked ZIP size lets us allocate once. The extra byte forces a
	// read through EOF, preserving CRC/size verification and rejecting a member
	// that expands beyond its declaration. Keep the per-member cap here too.
	if f.UncompressedSize64 > osvEntryMaxBytes {
		return nil, errors.New("OSV member exceeds size limit")
	}
	data := make([]byte, int(f.UncompressedSize64)+1)
	n := 0
	for {
		read, readErr := rc.Read(data[n:])
		n += read
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if n == len(data) {
			return nil, errors.New("OSV member exceeds declared size")
		}
	}
	if n != int(f.UncompressedSize64) {
		return nil, errors.New("OSV member size does not match declaration")
	}
	data = data[:n]
	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	if !validID(v.ID) {
		return nil, fmt.Errorf("invalid OSV advisory identifier %q", v.ID)
	}
	var versions int
	for _, affected := range v.Affected {
		if len(affected.Versions) > osvMaxVersions-versions {
			return nil, fmt.Errorf("OSV record exceeds %d total versions", osvMaxVersions)
		}
		versions += len(affected.Versions)
	}
	rec, ok := ConvertOSV(&v, source)
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// osvSource fetches per-ecosystem all.zip exports from OSV.
type osvSource struct{}

func (osvSource) Name() string { return SourceOSV }

func (osvSource) Feeds(opts *Options) ([]Feed, error) {
	base := strings.TrimRight(opts.OSVBaseURL, "/")
	if base == "" {
		base = DefaultOSVBaseURL
	}
	ecos := opts.Ecosystems
	if len(ecos) == 0 {
		ecos = DefaultOSVEcosystems
	}
	var feeds []Feed
	seen := map[string]bool{}
	for _, e := range ecos {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		if strings.ContainsAny(e, "/\\?#") {
			return nil, fmt.Errorf("invalid OSV ecosystem %q", e)
		}
		seen[e] = true
		eco := e
		feeds = append(feeds, Feed{
			Source:     SourceOSV,
			Key:        safeName(eco),
			URL:        base + "/" + eco + "/all.zip",
			File:       safeName(eco) + "-all.zip",
			Ecosystems: []string{eco},
			MaxBytes:   opts.MaxFeedBytes,
			Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
				_, err := parseOSVZipBounded(ctx, p, SourceOSV, nil, emit, progress, osvMaxEntries, opts.maxFeedUncompressedBytes())
				return err
			},
		})
	}
	if len(feeds) == 0 {
		return nil, errors.New("osv: no ecosystems selected")
	}
	return feeds, nil
}

// ghsaSource fetches the GitHub advisory-database repository archive and
// parses only the reviewed advisories.
type ghsaSource struct{}

func (ghsaSource) Name() string { return SourceGHSA }

func (ghsaSource) Feeds(opts *Options) ([]Feed, error) {
	u := opts.GHSAURL
	if u == "" {
		u = DefaultGHSAURL
	}
	max := opts.MaxFeedBytes
	if max <= 0 {
		max = GHSAMaxBytes
	}
	return []Feed{{
		Source:   SourceGHSA,
		Key:      "github-reviewed",
		URL:      u,
		File:     "advisory-database-main.zip",
		MaxBytes: max,
		Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
			_, err := parseOSVZipBounded(ctx, p, SourceGHSA, func(name string) bool {
				return strings.Contains(name, "/advisories/github-reviewed/") || strings.HasPrefix(name, "advisories/github-reviewed/")
			}, emit, progress, osvMaxEntries, opts.maxFeedUncompressedBytes())
			return err
		},
	}}, nil
}
