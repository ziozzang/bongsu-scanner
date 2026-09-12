package match

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

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
	affected  []preparedAffected
}
type preparedAffected struct {
	affected                 vulndb.Affected
	ecosystem, release, name string
	unimportant              bool
	severity, vector         string
	score                    float64
	exact                    map[string]bool
	anyValid                 bool
	ranges                   []preparedRange
	matches                  map[string]versionMatch
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
	versions    map[versionKey]versionInfo
	comparisons map[comparisonKey]comparison
}

func newVersionCache() *versionCache {
	return &versionCache{versions: make(map[versionKey]versionInfo), comparisons: make(map[comparisonKey]comparison)}
}
func (c *versionCache) get(eco, value string) versionInfo {
	key := versionKey{eco, value}
	if v, ok := c.versions[key]; ok {
		return v
	}
	v := versionInfo{version.Valid(eco, value), versionIdentifier(eco, value)}
	c.versions[key] = v
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
	c.comparisons[key] = result
	return result.order, result.ok, result.low
}
func (c *versionCache) prepareAffected(eco string, a vulndb.Affected) preparedAffected {
	out := preparedAffected{affected: a, ecosystem: vulndb.BaseEcosystem(a.Ecosystem), release: vulndb.EcosystemRelease(a.Ecosystem)}
	name := a.Package
	if name == "" && a.PURL != "" {
		if p, err := purl.Parse(a.PURL); err == nil {
			name = p.FullName()
		}
	}
	out.name = vulndb.NormalizeName(eco, name)
	out.unimportant = strings.EqualFold(fmt.Sprint(a.Database["urgency"]), "unimportant")
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
	out.affected.Versions = nil
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
	visit := func(r *vulndb.Record) error {
		out = append(out, prepareRecord(*r, cache, details, eco, name, versions, releases))
		return nil
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
		visit(&records[i])
	}
	return out, nil
}

func prepareRecord(r vulndb.Record, cache *versionCache, details bool, eco, name string, versions, releases map[string]bool) preparedRecord {
	rec := preparedRecord{ID: r.ID, Aliases: r.Aliases, Withdrawn: r.Withdrawn}
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
		prepared := cache.prepareAffected(vulndb.BaseEcosystem(a.Ecosystem), a)
		prepared.matches = make(map[string]versionMatch, len(versions))
		entryHit := false
		for v := range versions {
			hit, fixed, low, reason := cache.affectedVersion(eco, v, prepared)
			prepared.matches[v] = versionMatch{hit, fixed, low, reason}
			entryHit = entryHit || hit
		}
		anyHit = anyHit || entryHit
		if !entryHit {
			prepared.affected = vulndb.Affected{}
		} else {
			prepared.severity, prepared.score, prepared.vector = severity(r, a)
		}
		prepared.exact, prepared.ranges = nil, nil
		rec.affected = append(rec.affected, prepared)
	}
	if anyHit {
		summary := r.Summary
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
		rec.summary.Severity, rec.summary.Score, rec.summary.Vector = severity(r, vulndb.Affected{})
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
