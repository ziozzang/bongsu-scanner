package match

import (
	"context"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/version"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"sort"
	"strings"
)

type Options struct {
	Details            bool
	IncludeUnimportant bool
	MinSeverity        string
	IgnoreIDs          []string
	FailOn             string
	OnlyFixed          bool
}
type Finding struct {
	ID         string
	RelatedIDs []string
	Subject    Subject
	Record     RecordSummary
	Affected   vulndb.Affected
	MatchedBy  string
	FixedIn    []string
	Severity   string
	Score      float64
	Vector     string
	Confidence string
	Assessment *assessment.Result `json:"assessment,omitempty"`
}
type Report struct {
	Findings   []Finding
	Subjects   int
	Matched    int
	Skipped    map[string]int
	BySeverity map[string]int
	DB         vulndb.Meta
}

func Run(ctx context.Context, store vulndb.Store, subjects []Subject, opts Options) (Report, error) {
	report := Report{Subjects: len(subjects), Findings: make([]Finding, 0, len(subjects)), Skipped: map[string]int{}, BySeverity: map[string]int{}}
	meta, err := store.Meta()
	if err != nil {
		return report, err
	}
	report.DB = meta
	ecosystems, err := store.Ecosystems()
	if err != nil {
		return report, fmt.Errorf("database ecosystems: %w", err)
	}
	coverage := map[string]map[string]bool{}
	for _, e := range ecosystems {
		base := vulndb.BaseEcosystem(e)
		if coverage[base] == nil {
			coverage[base] = map[string]bool{}
		}
		coverage[base][vulndb.EcosystemRelease(e)] = true
	}

	ignored := map[string]bool{}
	for _, id := range opts.IgnoreIDs {
		ignored[strings.TrimSpace(id)] = true
	}
	cache := newLookupCache[[]preparedRecord](32 << 20)
	versions := newVersionCache()
	canonicalCache := newLookupCache[map[string]string](8 << 20)
	plans := map[string]*lookupPlan{}
	for i, s := range subjects {
		if subjectSkip(s, coverage) != "" {
			continue
		}
		for _, q := range subjectQueries(s) {
			key := s.Ecosystem + "\x00" + vulndb.NormalizeName(s.Ecosystem, q.name)
			plan := plans[key]
			if plan == nil {
				plan = new(lookupPlan)
				plans[key] = plan
			}
			plan.versions = appendDistinct(plan.versions, q.ver)
			plan.releases = appendDistinct(plan.releases, s.Release)
			plan.last = i
		}
	}
	found := map[string]int{}
	for si, s := range subjects {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if reason := subjectSkip(s, coverage); reason != "" {
			report.Skipped[reason]++
			continue
		}
		queries := subjectQueries(s)
		queryRecords := make([][]preparedRecord, len(queries))
		var canonicalKey string
		for qi, q := range queries {
			queries[qi].name = vulndb.NormalizeName(s.Ecosystem, q.name)
			key := s.Ecosystem + "\x00" + queries[qi].name
			records, ok := cache.get(key)
			// Reuse duplicate upstream/binary queries even when an oversized
			// result is deliberately excluded from the bounded shared cache.
			for previous := 0; previous < qi; previous++ {
				if queries[previous].name == queries[qi].name {
					records, ok = queryRecords[previous], true
					break
				}
			}
			if !ok {
				records, err = lookupPrepared(ctx, store, versions, opts.Details, s.Ecosystem, queries[qi].name, stringSet(plans[key].versions), stringSet(plans[key].releases))
				if err != nil {
					return report, fmt.Errorf("lookup %s/%s: %w", s.Ecosystem, q.name, err)
				}
				if plans[key].last > si {
					cache.put(key, records, preparedBytes(records))
				}
			}
			if len(records) > 0 {
				canonicalKey += key + "\x00"
			}
			queryRecords[qi] = records
		}
		for _, q := range queries {
			key := s.Ecosystem + "\x00" + q.name
			if plan := plans[key]; plan != nil && plan.last == si {
				cache.remove(key)
				delete(plans, key)
			}
		}
		canonical, ok := canonicalCache.get(canonicalKey)
		if !ok {
			var identities []advisoryIdentity
			for _, records := range queryRecords {
				for _, rec := range records {
					identities = append(identities, advisoryIdentity{rec.ID, rec.Aliases})
				}
			}
			canonical = aliasIdentityIDs(identities)
			canonicalCache.put(canonicalKey, canonical, canonicalBytes(canonical))
		}
		for qi, q := range queries {
			for _, rec := range queryRecords[qi] {
				if rec.Withdrawn != "" {
					report.Skipped["withdrawn"]++
					continue
				}
				id := canonical[rec.ID]
				skip := ignored[id] || ignored[rec.ID]
				for _, a := range rec.Aliases {
					skip = skip || ignored[a]
				}
				if skip {
					report.Skipped["ignored"]++
					continue
				}
				for _, prepared := range rec.affected {
					if prepared.version != q.ver {
						continue
					}
					if rel := prepared.release; rel != "" && rel != s.Release {
						continue
					}
					if !opts.IncludeUnimportant && prepared.unimportant {
						report.Skipped["unimportant"]++
						continue
					}
					result := prepared.versionMatch
					affected, fixed, low, reason := result.hit, result.fixed, result.low, result.reason
					if !affected {
						if reason != "" {
							report.Skipped[reason]++
						}
						continue
					}
					a := prepared.detail.affected
					sev, score, vector := prepared.detail.severity, prepared.detail.score, prepared.detail.vector
					if opts.MinSeverity != "" && SeverityRank(sev) < SeverityRank(opts.MinSeverity) {
						continue
					}
					if opts.OnlyFixed && len(fixed) == 0 {
						continue
					}
					f := Finding{ID: id, RelatedIDs: rec.related, Subject: s, Record: *rec.summary, Affected: a, MatchedBy: q.by, FixedIn: fixed, Severity: sev, Score: score, Vector: vector, Confidence: "high"}
					if low {
						f.Confidence = "low"
					}
					fk := s.Ref + "\x00" + id
					if at, ok := found[fk]; ok {
						mergeFinding(&report.Findings[at], f)
					} else {
						found[fk] = len(report.Findings)
						report.Findings = append(report.Findings, f)
					}
				}
			}
		}
	}
	matched := map[string]bool{}
	for _, f := range report.Findings {
		matched[f.Subject.Ref] = true
		report.BySeverity[f.Severity]++
	}
	report.Matched = len(matched)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
			return SeverityRank(a.Severity) > SeverityRank(b.Severity)
		}
		if a.Subject.Name != b.Subject.Name {
			return a.Subject.Name < b.Subject.Name
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject.Ref < b.Subject.Ref
	})
	return report, nil
}

func subjectSkip(s Subject, coverage map[string]map[string]bool) string {
	if s.Ecosystem == "" {
		return "unknown-ecosystem"
	}
	releases, present := coverage[s.Ecosystem]
	if !present {
		return "ecosystem-not-in-database"
	}
	if s.Release == "" && (!releases[""] || s.Ecosystem == "Debian" || s.Ecosystem == "Ubuntu" || s.Ecosystem == "Alpine") {
		return "release-unknown"
	}
	if !releases[""] && !releases[s.Release] {
		return "release-not-in-database"
	}
	// A source version is sufficient for distribution upstream queries.
	if s.Version == "" && s.UpstreamVersion == "" {
		return "missing-version"
	}
	return ""
}

type query struct{ name, by, ver string }

func subjectQueries(s Subject) []query {
	queries := []query{{s.Name, "purl-name", s.Version}}
	if s.Type == "deb" || s.Type == "apk" || s.Type == "rpm" {
		queries[0].by = "binary-name"
		if s.UpstreamVersion != "" {
			queries[0].ver = s.UpstreamVersion
		}
		if s.Upstream != "" {
			v := s.Version
			if s.UpstreamVersion != "" {
				v = s.UpstreamVersion
			}
			queries = append([]query{{s.Upstream, "upstream", v}}, queries...)
		}
	}
	return queries
}

func canonicalID(r vulndb.Record) string {
	var cves []string
	for _, id := range append([]string{r.ID}, r.Aliases...) {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		}
	}
	if len(unique(cves)) == 1 {
		return cves[0]
	}
	if len(cves) > 1 {
		// Multiple CVE aliases may represent distinct advisories sharing
		// history (for example an incomplete fix). Do not guess which CVE
		// is canonical or merge those records into one finding.
		return r.ID
	}
	if len(cves) > 0 {
		return cves[0]
	}
	return r.ID
}

// aliasCanonicalIDs resolves aliases in either direction across every lookup
// for a subject. Multi-CVE records stay independent, as in canonicalID.
type advisoryIdentity struct {
	ID      string
	Aliases []string
}

func aliasCanonicalIDs(records []vulndb.Record) map[string]string {
	identities := make([]advisoryIdentity, len(records))
	for i, r := range records {
		identities[i] = advisoryIdentity{r.ID, r.Aliases}
	}
	return aliasIdentityIDs(identities)
}

func aliasIdentityIDs(records []advisoryIdentity) map[string]string {
	parent := map[string]string{}
	protected := map[string]bool{}
	for _, r := range records {
		var cves []string
		for _, id := range append([]string{r.ID}, r.Aliases...) {
			if strings.HasPrefix(id, "CVE-") {
				cves = append(cves, id)
			}
		}
		if len(unique(cves)) > 1 {
			protected[r.ID] = true
		}
	}
	var find func(string) string
	find = func(id string) string {
		p, ok := parent[id]
		if !ok {
			parent[id] = id
			return id
		}
		if p != id {
			parent[id] = find(p)
		}
		return parent[id]
	}
	for _, r := range records {
		find(r.ID)
		if protected[r.ID] {
			continue
		}
		for _, alias := range r.Aliases {
			if alias != "" && !protected[alias] {
				parent[find(alias)] = find(r.ID)
			}
		}
	}
	groups := map[string][]string{}
	for id := range parent {
		root := find(id)
		groups[root] = append(groups[root], id)
	}
	canonical := map[string]string{}
	for root, ids := range groups {
		sort.Strings(ids)
		canonical[root] = canonicalID(vulndb.Record{ID: ids[0], Aliases: ids[1:]})
		var cves int
		for _, id := range ids {
			if strings.HasPrefix(id, "CVE-") {
				cves++
			}
		}
		if cves > 1 {
			// Transitive aliases can also introduce ambiguity; do not collapse
			// distinct CVEs through a shared non-CVE identifier.
			delete(canonical, root)
		}
	}
	result := map[string]string{}
	for _, r := range records {
		id, ok := canonical[find(r.ID)]
		if !ok || protected[r.ID] {
			id = canonicalID(vulndb.Record{ID: r.ID, Aliases: r.Aliases})
		}
		result[r.ID] = id
	}
	return result
}

func unique(ss []string) []string {
	m := map[string]bool{}
	for _, s := range ss {
		if s != "" {
			m[s] = true
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func mergeFinding(dst *Finding, src Finding) {
	dst.RelatedIDs = unique(append(dst.RelatedIDs, src.RelatedIDs...))
	dst.FixedIn = unique(append(dst.FixedIn, src.FixedIn...))
	if SeverityRank(src.Severity) > SeverityRank(dst.Severity) || (SeverityRank(src.Severity) == SeverityRank(dst.Severity) && src.Score > dst.Score) {
		dst.Severity, dst.Score, dst.Vector = src.Severity, src.Score, src.Vector
	}
	if src.Confidence == "high" {
		dst.Confidence = "high"
	}
}

// compare rejects unknown ordering. Exact identity remains usable with low
// confidence when an ecosystem's grammar cannot parse the version.
func compare(eco, a, b string) (int, bool, bool) {
	c, e := version.Compare(eco, a, b)
	if e == nil && version.Valid(eco, a) && version.Valid(eco, b) {
		return c, true, false
	}
	if a == b {
		return 0, true, true
	}
	return 0, false, true
}

// versionIdentifier normalizes spelling without discarding build metadata,
// which is significant for explicit versions even when ordering ignores it.
func versionIdentifier(eco, v string) string {
	v = strings.TrimSpace(v)
	normalized := version.Normalize(eco, v)
	switch strings.ToLower(vulndb.BaseEcosystem(eco)) {
	case "pypi", "python", "pip":
		if version.Valid(eco, v) {
			// PEP 440 release identifiers ignore trailing zero segments.
			start := strings.IndexByte(normalized, '!') + 1
			end := start
			for end < len(normalized) {
				c := normalized[end]
				if (c >= '0' && c <= '9') || (c == '.' && end+1 < len(normalized) && normalized[end+1] >= '0' && normalized[end+1] <= '9') {
					end++
				} else {
					break
				}
			}
			core := normalized[start:end]
			for strings.HasSuffix(core, ".0") {
				core = strings.TrimSuffix(core, ".0")
			}
			normalized = normalized[:start] + core + normalized[end:]
		}
	}
	if i := strings.IndexByte(v, '+'); i >= 0 && !strings.Contains(normalized, "+") {
		normalized += v[i:]
	}
	return normalized
}

func affectedVersion(eco, v string, a vulndb.Affected) (bool, []string, bool, string) {
	cache := newVersionCache()
	return cache.affectedVersion(eco, v, cache.prepareAffected(eco, a))
}

func (cache *versionCache) affectedVersion(eco, v string, a preparedAffected) (bool, []string, bool, string) {
	hit, low, usable := false, false, false
	var fixed []string
	subject := cache.get(eco, v)
	usable = subject.valid && a.anyValid
	if exact, ok := a.exact[subject.identifier]; ok {
		hit, usable = true, true
		low = !subject.valid || !exact
	}
	for _, r := range a.ranges {
		if r.source.Type != "ECOSYSTEM" && r.source.Type != "SEMVER" {
			continue
		}
		cmpEco := eco
		if r.source.Type == "SEMVER" {
			cmpEco = "semver"
		}
		if !cache.get(cmpEco, v).valid {
			continue
		}
		events, valid := r.events, r.valid
		if !valid {
			continue
		}
		// Limits constrain the entire range, independently of its intervals.
		hasLimits, beforeLimits := false, false
		for _, ev := range r.source.Events {
			if ev.Limit != "" {
				hasLimits = true
				if ev.Limit == "*" {
					beforeLimits = true
				} else if c, ok, _ := cache.compare(cmpEco, v, ev.Limit); ok && c < 0 {
					beforeLimits = true
				}
			}
		}
		affected, endpointSeen := false, false
		var rangeFixed []string
		for _, ev := range events {
			switch {
			case ev.Introduced != "":
				usable = true
				c, _, _ := cache.compare(cmpEco, v, ev.Introduced)
				if ev.Introduced == "0" || c >= 0 {
					affected = true
				}
			case ev.Fixed != "":
				c, _, _ := cache.compare(cmpEco, v, ev.Fixed)
				if c >= 0 {
					affected = false
				} else if affected && !endpointSeen {
					rangeFixed = append(rangeFixed, ev.Fixed)
				}
				endpointSeen = endpointSeen || c < 0
			case ev.LastAffected != "":
				c, _, _ := cache.compare(cmpEco, v, ev.LastAffected)
				if c > 0 {
					affected = false
				}
				endpointSeen = endpointSeen || c <= 0
			}
		}
		if affected && (!hasLimits || beforeLimits) {
			hit = true
			fixed = append(fixed, rangeFixed...)
		}
	}
	fixed = unique(fixed)
	sort.SliceStable(fixed, func(i, j int) bool {
		c, ok, _ := cache.compare(eco, fixed[i], fixed[j])
		if ok {
			return c < 0
		}
		return fixed[i] < fixed[j]
	})
	reason := ""
	if !usable {
		reason = "no-usable-range"
	}
	return hit, fixed, low, reason
}
func SeverityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM", "MODERATE":
		return 3
	case "LOW":
		return 2
	case "NEGLIGIBLE", "NONE", "INFO":
		return 1
	default:
		return 0
	}
}
func ShouldFail(r Report, threshold string) bool {
	if threshold == "" {
		return false
	}
	for _, f := range r.Findings {
		if SeverityRank(f.Severity) >= SeverityRank(threshold) {
			return true
		}
	}
	return false
}

// sortedEvents handles OSV feeds whose events are not in version order.
// Invalid boundaries cannot establish a trustworthy affected interval.
func sortedEvents(eco string, in []vulndb.Event) ([]vulndb.Event, bool) {
	return newVersionCache().sortedEvents(eco, in)
}
func (cache *versionCache) sortedEvents(eco string, in []vulndb.Event) ([]vulndb.Event, bool) {
	events := make([]vulndb.Event, 0, len(in))
	value := func(e vulndb.Event) string {
		for _, v := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
			if v != "" {
				return v
			}
		}
		return ""
	}
	for _, e := range in {
		n := 0
		for _, v := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
			if v != "" {
				n++
			}
		}
		if n != 1 {
			return nil, false
		}
		if e.Introduced != "0" && e.Limit != "*" && !cache.get(eco, value(e)).valid {
			return nil, false
		}
		if e.Limit == "" {
			events = append(events, e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.Introduced == "0" {
			return b.Introduced != "0"
		}
		if b.Introduced == "0" {
			return false
		}
		c, ok, _ := cache.compare(eco, value(a), value(b))
		if !ok {
			return false
		}
		if c == 0 {
			return a.Introduced == "" && b.Introduced != ""
		}
		return c < 0
	})
	return events, true
}
