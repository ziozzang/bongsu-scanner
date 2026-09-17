package match

import (
	"context"
	"fmt"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/version"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// Deliberately small: generic package names alone are not globally unique.
var cpeAliases = map[string]string{
	"python": "python:python", "cpython": "python:python", "openssl": "openssl:openssl",
	"node": "nodejs:node.js", "nodejs": "nodejs:node.js", "php": "php:php", "ruby": "ruby-lang:ruby",
}

func subjectCPE(s Subject) ([]vulndb.CPEAttribute, bool) {
	raw := s.CPE
	if raw == "" && s.PURL.Type == "generic" && s.PURL.Namespace == "" {
		if pair := cpeAliases[strings.ToLower(s.PURL.Name)]; pair != "" {
			raw = "cpe:2.3:a:" + pair + ":*:*:*:*:*:*:*:*"
		}
	}
	attrs, ok := vulndb.ParseCPE(raw)
	if !ok || attrs[1].Kind != vulndb.CPELiteral || attrs[2].Kind != vulndb.CPELiteral {
		return nil, false
	}
	return attrs, true
}
func concreteCPE(value string) bool {
	return value != "" && value != "-" && !strings.ContainsAny(value, "*?")
}

func compareCPE(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	// Semver handles prereleases correctly when both inputs parse; vendor versions
	// such as OpenSSL 1.0.2u retain the generic numeric/text ordering.
	if c, err := version.CompareSemver(a, b); err == nil {
		return c
	}
	return version.CompareGeneric(a, b)
}

func cpeVersionMatch(s Subject, subject, criteria []vulndb.CPEAttribute, a vulndb.Affected) (bool, bool, []string) {
	v := strings.ToLower(s.Version)
	if v == "" && subject[3].Kind == vulndb.CPELiteral {
		v = subject[3].Value
	} else if !concreteCPE(v) && !(subject[3].Kind == vulndb.CPELiteral && v == subject[3].Value) {
		return false, false, nil
	}
	if subject[3].Kind == vulndb.CPELiteral && compareCPE(v, subject[3].Value) != 0 {
		return false, false, nil
	}
	exact := criteria[3].Kind == vulndb.CPELiteral
	if criteria[3].Kind != vulndb.CPEAny && (!exact || v != criteria[3].Value) {
		return false, false, nil
	}
	if lower, _ := a.Database["versionStartExcluding"].(string); lower != "" && compareCPE(v, lower) <= 0 {
		return false, false, nil
	}
	if len(a.Ranges) == 0 {
		// Exact criteria are authoritative, including records cached before
		// ingestion began unescaping Versions and recognizing escaped wildcards.
		if exact {
			return true, true, nil
		}
		for _, candidate := range a.Versions {
			if v == strings.ToLower(candidate) {
				return true, exact, nil
			}
		}
		return false, false, nil
	}
	for _, r := range a.Ranges {
		if r.Type != "ECOSYSTEM" {
			continue
		}
		active := false
		for _, event := range r.Events {
			if event.Introduced != "" {
				active = event.Introduced == "0" || compareCPE(v, event.Introduced) >= 0
			}
			if event.Fixed != "" {
				if active && compareCPE(v, event.Fixed) < 0 {
					return true, false, []string{event.Fixed}
				}
				active = false
			}
			if event.LastAffected != "" {
				if active && compareCPE(v, event.LastAffected) <= 0 {
					return true, false, nil
				}
				active = false
			}
			if event.Limit != "" {
				if active && compareCPE(v, event.Limit) < 0 {
					return true, false, nil
				}
				active = false
			}
		}
		if active {
			return true, false, nil
		}
	}
	return false, false, nil
}

func cpeAttributesMatch(s Subject, subject, criteria []vulndb.CPEAttribute) bool {
	for i := 0; i < 3; i++ {
		if subject[i].Kind != criteria[i].Kind || subject[i].Value != criteria[i].Value {
			return false
		}
	}
	for i := 4; i < len(criteria); i++ {
		if criteria[i].Kind == vulndb.CPEAny {
			continue
		}
		if criteria[i].Kind == vulndb.CPEPattern {
			return false
		}
		if criteria[i].Kind == subject[i].Kind && criteria[i].Value == subject[i].Value {
			continue
		}
		// target_sw may describe a known ecosystem even when the inventory CPE
		// omitted it. Never infer hardware, edition, language, or update attributes.
		if i == 8 && subject[i].Kind == vulndb.CPEAny && criteria[i].Kind == vulndb.CPELiteral && (strings.EqualFold(criteria[i].Value, s.Ecosystem) || strings.EqualFold(criteria[i].Value, s.PURL.Type)) {
			continue
		}
		return false
	}
	return true
}

func matchCPE(ctx context.Context, store vulndb.Store, subjects []Subject, opts Options, ignored map[string]bool, versions *versionCache, report *Report) error {
	reader, ok := store.(vulndb.CPEStore)
	if !ok {
		return fmt.Errorf("database does not support CPE lookup")
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		for _, id := range append(append([]string{f.ID, f.Record.ID}, f.RelatedIDs...), f.Record.Aliases...) {
			seen[f.Subject.Ref+"\x00"+id] = true
		}
	}
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		attrs, ok := subjectCPE(s)
		if !ok {
			continue
		}
		var records []vulndb.Record
		var err error
		if contextual, ok := reader.(interface {
			LookupCPEContext(context.Context, string, string) ([]vulndb.Record, error)
		}); ok {
			records, err = contextual.LookupCPEContext(ctx, attrs[1].Formatted(), attrs[2].Formatted())
		} else {
			records, err = reader.LookupCPE(attrs[1].Formatted(), attrs[2].Formatted())
		}
		if err != nil {
			return fmt.Errorf("CPE lookup %s:%s: %w", attrs[1].Formatted(), attrs[2].Formatted(), err)
		}
		for _, r := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if r.Withdrawn != "" {
				continue
			}
			ids := append([]string{r.ID}, r.Aliases...)
			skip := false
			for _, id := range ids {
				skip = skip || seen[s.Ref+"\x00"+id] || ignored[id]
			}
			if skip {
				continue
			}
			var best *Finding
			for _, a := range r.Affected {
				if a.Ecosystem != "CPE" {
					continue
				}
				if a.Database["requires_and"] == true || a.Database["operator"] == "AND" {
					report.Skipped["cpe-requires-and"]++
					continue
				}
				if a.Database["negate"] == true || a.Database["node_children"] == true {
					continue
				}
				if operator, _ := a.Database["operator"].(string); operator != "OR" {
					continue
				}
				raw, _ := a.Database["cpe"].(string)
				criteria, ok := vulndb.ParseCPE(raw)
				if !ok || criteria[1].Kind != vulndb.CPELiteral || criteria[2].Kind != vulndb.CPELiteral || !cpeAttributesMatch(s, attrs, criteria) {
					continue
				}
				hit, exact, fixed := cpeVersionMatch(s, attrs, criteria, a)
				if !hit || opts.OnlyFixed && len(fixed) == 0 {
					continue
				}
				sev, score, vector := versions.severity(r, a)
				summary := RecordSummary{ID: r.ID, Aliases: r.Aliases, Summary: r.Summary, Published: r.Published, Modified: r.Modified, Source: r.Source, Severity: sev, Score: score, Vector: vector,
					assessmentText: &advisoryText{r.Summary, r.Details, vulndb.DetailsMayBeTruncated(r), r.References}}
				if opts.Details {
					summary.Details = r.Details
					summary.DetailsTruncated = r.DetailsTruncated
				}
				for _, ref := range r.References {
					if len(summary.References) == 5 {
						break
					}
					summary.References = append(summary.References, ref.URL)
				}
				confidence := "low"
				if exact {
					confidence = "high"
				}
				f := Finding{ID: canonicalID(r), RelatedIDs: unique(ids), Subject: s, Record: summary, Affected: a, MatchedBy: "cpe", FixedIn: fixed, Severity: sev, Score: score, Vector: vector, Confidence: confidence}
				if best == nil || best.Confidence == "low" && exact {
					best = &f
				}
			}
			if best != nil {
				report.Findings = append(report.Findings, *best)
				for _, id := range ids {
					seen[s.Ref+"\x00"+id] = true
				}
			}
		}
	}
	return ctx.Err()
}
