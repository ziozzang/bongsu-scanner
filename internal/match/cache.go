package match

import (
	"container/list"
	"context"
	"sort"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/version"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// RecordSummary deliberately excludes the full advisory and its affected lists.
// Details is opt-in; private assessment text preserves the existing LLM input.
type RecordSummary struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	Details          string   `json:"details,omitempty"`
	DetailsTruncated bool     `json:"details_truncated,omitempty"`
	Published        string   `json:"published,omitempty"`
	Modified         string   `json:"modified,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	DistroSeverity   string   `json:"distro_severity,omitempty"`
	Score            float64  `json:"score,omitempty"`
	Vector           string   `json:"vector,omitempty"`
	Source           string   `json:"source"`
	References       []string `json:"references,omitempty"`
	Withdrawn        string   `json:"withdrawn,omitempty"`
	assessmentText   *advisoryText
}

type advisoryText struct {
	summary, details string
	truncated        bool
	references       []vulndb.Reference
}

type preparedRecord struct {
	ID        string
	Aliases   []string
	Withdrawn string
	summary   *RecordSummary
	related   []string
	affected  []evaluatedAffected
}

// Only evaluated outcomes survive the visitor; parsed version ranges and maps
// are scratch space for one affected entry. RPM misses retain a row so module
// mismatches can be counted before deciding applicability for each subject.
type evaluatedAffected struct {
	modular                      bool
	version, release             string
	unimportant                  bool
	distroStatus, distroSeverity string
	versionMatch
	detail *findingAffected
}
type findingAffected struct {
	affected         vulndb.Affected
	severity, vector string
	score            float64
}
type preparedAffected struct {
	exact    map[string]bool
	anyValid bool
	ranges   []preparedRange
}
type versionMatch struct {
	hit    bool
	fixed  []string
	low    bool
	reason string
}
type preparedRange struct {
	source vulndb.Range
	events []vulndb.Event
	valid  bool
}
type versionKey struct{ ecosystem, value string }
type versionInfo struct {
	valid      bool
	identifier string
}
type comparisonKey struct{ ecosystem, a, b string }
type comparison struct {
	order   int
	ok, low bool
}

// All caches belong to one Run. No global state or synchronization is needed.
type versionCache struct {
	versions                      map[versionKey]versionInfo
	comparisons                   map[comparisonKey]comparison
	versionBytes, comparisonBytes int
	cvss                          map[string]cvssResult
}

func newVersionCache() *versionCache {
	return &versionCache{versions: make(map[versionKey]versionInfo), comparisons: make(map[comparisonKey]comparison), cvss: make(map[string]cvssResult)}
}
func (c *versionCache) get(eco, value string) versionInfo {
	key := versionKey{eco, value}
	if v, ok := c.versions[key]; ok {
		return v
	}
	v := versionInfo{version.Valid(eco, value), versionIdentifier(eco, value)}
	size := 96 + len(eco) + len(value) + len(v.identifier)
	if c.versionBytes+size > 1<<20 {
		clear(c.versions)
		c.versionBytes = 0
	}
	if size <= 1<<20 {
		c.versions[key] = v
		c.versionBytes += size
	}
	return v
}
func (c *versionCache) compare(eco, a, b string) (int, bool, bool) {
	key := comparisonKey{eco, a, b}
	if result, ok := c.comparisons[key]; ok {
		return result.order, result.ok, result.low
	}
	result := comparison{low: true}
	if c.get(eco, a).valid && c.get(eco, b).valid {
		order, err := version.Compare(eco, a, b)
		if err == nil {
			result = comparison{order: order, ok: true}
		}
	}
	if !result.ok && a == b {
		result.ok = true
	}
	size := 96 + len(eco) + len(a) + len(b)
	if c.comparisonBytes+size > 2<<20 {
		clear(c.comparisons)
		c.comparisonBytes = 0
	}
	if size <= 2<<20 {
		c.comparisons[key] = result
		c.comparisonBytes += size
	}
	return result.order, result.ok, result.low
}
func (c *versionCache) prepareAffected(eco string, a vulndb.Affected) preparedAffected {
	out := preparedAffected{}
	if len(a.Versions) > 0 {
		out.exact = make(map[string]bool)
	}
	for _, exact := range a.Versions {
		v := c.get(eco, exact)
		out.anyValid = out.anyValid || v.valid
		valid := v.valid
		if previous, ok := out.exact[v.identifier]; ok {
			valid = valid && previous
		}
		out.exact[v.identifier] = valid
	}
	for _, r := range a.Ranges {
		cmpEco := eco
		if r.Type == "SEMVER" {
			cmpEco = "semver"
		}
		events, valid := c.sortedEvents(cmpEco, r.Events)
		out.ranges = append(out.ranges, preparedRange{r, events, valid})
	}
	return out
}

// Consume a SQLite result one record at a time. Legacy stores keep their
// existing API; preparation never modifies their shared records.
func lookupPrepared(ctx context.Context, store vulndb.Store, cache *versionCache, details bool, eco, name string, versions, releases map[string]bool) ([]preparedRecord, error) {
	var out []preparedRecord
	orderedVersions := make([]string, 0, len(versions))
	for v := range versions {
		orderedVersions = append(orderedVersions, v)
	}
	sort.Strings(orderedVersions)
	visit := func(r *vulndb.Record) error {
		out = append(out, prepareRecord(*r, cache, details, eco, name, orderedVersions, releases))
		return nil
	}
	if reader, ok := store.(interface {
		LookupMatchingFunc(context.Context, string, string, func(*vulndb.Record) error) error
	}); ok {
		err := reader.LookupMatchingFunc(ctx, eco, name, visit)
		return out, err
	}
	if reader, ok := store.(interface {
		LookupFunc(context.Context, string, string, func(*vulndb.Record) error) error
	}); ok {
		err := reader.LookupFunc(ctx, eco, name, visit)
		return out, err
	}
	records, err := vulndb.LookupContext(ctx, store, eco, name)
	if err != nil {
		return nil, err
	}
	out = make([]preparedRecord, 0, len(records))
	for i := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// This local visitor only appends records and always returns nil.
		_ = visit(&records[i])
	}
	return out, nil
}

func prepareRecord(r vulndb.Record, cache *versionCache, details bool, eco, name string, versions []string, releases map[string]bool) preparedRecord {
	rec := preparedRecord{ID: r.ID, Aliases: r.Aliases, Withdrawn: r.Withdrawn}
	if r.Withdrawn != "" {
		return rec
	}
	anyHit := false
	for _, a := range r.Affected {
		if vulndb.BaseEcosystem(a.Ecosystem) != eco {
			continue
		}
		if release := vulndb.EcosystemRelease(a.Ecosystem); release != "" && !releases[release] {
			continue
		}
		packageName := a.Package
		if packageName == "" && a.PURL != "" {
			if p, err := purl.Parse(a.PURL); err == nil {
				packageName = p.FullName()
			}
		}
		if vulndb.NormalizeName(eco, packageName) != name {
			continue
		}
		modular := moduleAffected(a)
		prepared := cache.prepareAffected(eco, a)
		release := vulndb.EcosystemRelease(a.Ecosystem)
		urgency := distroSeverity(r, a)
		status, _ := a.Database["debian_status"].(string)
		status = strings.ToLower(strings.TrimSpace(status))
		marker := len(a.Ranges) == 0 && len(a.Versions) == 0
		// Older native not-affected markers used the empty [0,0) range.
		// Keep that exact representation equivalent to a range-free marker.
		if status == "not-affected" && len(a.Versions) == 0 && len(a.Ranges) == 1 {
			r := a.Ranges[0]
			marker = r.Type == "ECOSYSTEM" && r.Repo == "" && len(r.Events) == 2 && r.Events[0] == (vulndb.Event{Introduced: "0"}) && r.Events[1] == (vulndb.Event{Fixed: "0"})
		}
		var detail *findingAffected
		for _, v := range versions {
			hit, fixed, low, reason := cache.affectedVersion(eco, v, prepared)
			entryStatus, entryUrgency := status, urgency
			if !hit && !marker {
				entryStatus, entryUrgency = "", ""
			}
			if !hit && reason == "" && entryStatus == "" && entryUrgency == "" && !rpmEcosystem(eco) {
				continue
			}
			if hit && detail == nil {
				a.Versions = nil
				sev, score, vector := cache.severity(r, a)
				detail = &findingAffected{affected: a, severity: sev, score: score, vector: vector}
			}
			result := evaluatedAffected{modular: modular, version: v, release: release, unimportant: entryUrgency == "unimportant" || entryUrgency == "negligible", distroStatus: entryStatus, distroSeverity: entryUrgency, versionMatch: versionMatch{hit, fixed, low, reason}}
			// A range-free unimportant/negligible marker can be counted as
			// excluded, but cannot lower a positive alias entry's rating.
			if !hit && result.unimportant {
				result.distroSeverity = ""
			}
			if hit {
				result.detail = detail
			}
			rec.affected = append(rec.affected, result)
			anyHit = anyHit || hit
		}
	}
	if anyHit {
		var summary string
		// A bounded rune walk also handles one-byte and malformed input safely.
		for n, at := 0, 0; ; n++ {
			if n == 500 {
				summary = strings.Clone(r.Summary[:at])
				break
			}
			if at >= len(r.Summary) {
				summary = r.Summary
				break
			}
			_, size := utf8.DecodeRuneInString(r.Summary[at:])
			at += size
		}
		rec.related = unique(append([]string{r.ID}, r.Aliases...))
		rec.summary = &RecordSummary{ID: r.ID, Aliases: r.Aliases, Summary: summary, Published: r.Published, Modified: r.Modified, Source: r.Source, Withdrawn: r.Withdrawn}
		rec.summary.DistroSeverity = distroSeverity(r, vulndb.Affected{})
		rec.summary.Severity, rec.summary.Score, rec.summary.Vector = cache.severity(r, vulndb.Affected{})
		rec.summary.assessmentText = &advisoryText{r.Summary, r.Details, vulndb.DetailsMayBeTruncated(r), r.References}
		if details {
			rec.summary.Details = r.Details
			rec.summary.DetailsTruncated = r.DetailsTruncated
		}
		for _, ref := range r.References {
			if len(rec.summary.References) == 5 {
				break
			}
			rec.summary.References = append(rec.summary.References, ref.URL)
		}

	}
	return rec
}

// Plans normally contain one version and release. Slices avoid two hash tables
// per SBOM package; maps are only constructed when a lookup actually runs.
type lookupPlan struct {
	versions, releases []string
	last               int
}

func appendDistinct(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

// LRU order depends solely on subject/query order. Costs include referenced
// payloads, conservatively counting shared data more than once. Oversize
// lookups are consumed by the caller but never pinned in the cache.
type lookupCache[T any] struct {
	entries      map[string]*list.Element
	lru          list.List
	bytes, limit int64
}
type lookupCacheEntry[T any] struct {
	key   string
	value T
	bytes int64
}

func newLookupCache[T any](limit int64) *lookupCache[T] {
	return &lookupCache[T]{entries: make(map[string]*list.Element), limit: limit}
}
func (c *lookupCache[T]) get(key string) (T, bool) {
	if e := c.entries[key]; e != nil {
		c.lru.MoveToFront(e)
		return e.Value.(lookupCacheEntry[T]).value, true
	}
	var zero T
	return zero, false
}
func (c *lookupCache[T]) remove(key string) {
	if e := c.entries[key]; e != nil {
		c.bytes -= e.Value.(lookupCacheEntry[T]).bytes
		delete(c.entries, key)
		c.lru.Remove(e)
	}
}
func (c *lookupCache[T]) put(key string, value T, size int64) {
	c.remove(key)
	size += int64(len(key)) + 128 // map slot, entry and list links
	if size > c.limit {
		return
	}
	for c.bytes+size > c.limit {
		c.remove(c.lru.Back().Value.(lookupCacheEntry[T]).key)
	}
	c.entries[key] = c.lru.PushFront(lookupCacheEntry[T]{key, value, size})
	c.bytes += size
}
func stringBytes(values []string) int64 {
	n := int64(cap(values)) * 16
	for _, value := range values {
		n += int64(len(value))
	}
	return n
}
func jsonValueBytes(value any) int64 { return jsonValueBytesDepth(value, 0) }
func jsonValueBytesDepth(value any, depth int) int64 {
	// Foreign Store implementations can supply deeply nested or cyclic values.
	// Refuse to cache them instead of recursing without a bound.
	if depth > 64 {
		return 1 << 40
	}
	switch v := value.(type) {
	case string:
		return 16 + int64(len(v))
	case []any:
		n := int64(cap(v)) * 16
		for _, x := range v {
			n += jsonValueBytesDepth(x, depth+1)
		}
		return n
	case map[string]any:
		n := int64(64 + len(v)*64)
		for k, x := range v {
			n += int64(len(k)) + jsonValueBytesDepth(x, depth+1)
		}
		return n
	default:
		return 16
	}
}
func affectedBytes(a vulndb.Affected) int64 {
	n := int64(unsafe.Sizeof(a)) + int64(len(a.Ecosystem)+len(a.Package)+len(a.PURL))
	n += stringBytes(a.Versions) + jsonValueBytes(a.Database) + jsonValueBytes(a.Specific)
	n += int64(cap(a.Ranges)) * int64(unsafe.Sizeof(vulndb.Range{}))
	for _, r := range a.Ranges {
		n += int64(len(r.Type)+len(r.Repo)) + int64(cap(r.Events))*int64(unsafe.Sizeof(vulndb.Event{}))
		for _, e := range r.Events {
			n += int64(len(e.Introduced) + len(e.Fixed) + len(e.LastAffected) + len(e.Limit))
		}
	}
	n += int64(cap(a.Severity)) * 32
	for _, sev := range a.Severity {
		n += int64(len(sev.Type) + len(sev.Score))
	}
	return n
}
func preparedBytes(records []preparedRecord) int64 {
	n := int64(cap(records)) * int64(unsafe.Sizeof(preparedRecord{}))
	for _, r := range records {
		n += int64(len(r.ID)+len(r.Withdrawn)) + stringBytes(r.Aliases) + stringBytes(r.related)
		n += int64(cap(r.affected)) * int64(unsafe.Sizeof(evaluatedAffected{}))
		for _, a := range r.affected {
			n += int64(len(a.version)+len(a.release)+len(a.reason)+len(a.distroStatus)+len(a.distroSeverity)) + stringBytes(a.fixed)
			if a.detail != nil {
				n += affectedBytes(a.detail.affected) + 40 + int64(len(a.detail.severity)+len(a.detail.vector))
			}
		}
		if s := r.summary; s != nil {
			n += int64(unsafe.Sizeof(*s)) + int64(len(s.ID)+len(s.Summary)+len(s.Details)+len(s.Published)+len(s.Modified)+len(s.Severity)+len(s.DistroSeverity)+len(s.Vector)+len(s.Source)+len(s.Withdrawn)) + stringBytes(s.Aliases) + stringBytes(s.References)
			if a := s.assessmentText; a != nil {
				n += int64(unsafe.Sizeof(*a)) + int64(len(a.summary)+len(a.details)) + int64(cap(a.references))*32
				for _, ref := range a.references {
					n += int64(len(ref.Type) + len(ref.URL))
				}
			}
		}
	}
	return n
}
func canonicalBytes(values map[string]string) int64 {
	n := int64(64 + len(values)*96)
	for k, v := range values {
		n += int64(len(k) + len(v))
	}
	return n
}

func moduleAffected(a vulndb.Affected) bool {
	for _, v := range a.Versions {
		if strings.Contains(v, ".module+") {
			return true
		}
	}
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			if strings.Contains(e.Fixed, ".module+") || strings.Contains(e.Introduced, ".module+") || strings.Contains(e.LastAffected, ".module+") {
				return true
			}
		}
	}
	return false
}

func rpmEcosystem(eco string) bool {
	switch eco {
	case "Red Hat", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE":
		return true
	}
	return false
}
