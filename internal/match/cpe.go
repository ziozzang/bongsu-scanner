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
	"node": "nodejs:node.js", "nodejs": "nodejs:node.js", "php": "php:php", "ruby": "ruby:ruby",
}

func subjectCPE(s Subject) ([]string, bool) {
	raw := s.CPE
	if raw == "" && s.PURL.Type == "generic" && s.PURL.Namespace == "" {
		if pair := cpeAliases[strings.ToLower(s.PURL.Name)]; pair != "" {
			raw = "cpe:2.3:a:" + pair + ":*:*:*:*:*:*:*:*"
		}
	}
	attrs, ok := vulndb.CPEAttributes(raw)
	if !ok || !concreteCPE(attrs[1]) || !concreteCPE(attrs[2]) {
		return nil, false
	}
	return attrs, true
}
func concreteCPE(value string) bool {
	return value != "" && value != "-" && !strings.ContainsAny(value, "*?")
}

func compareCPE(a, b string) int {
	// Semver handles prereleases correctly when both inputs parse; vendor versions
	// such as OpenSSL 1.0.2u retain the generic numeric/text ordering.
	if c, err := version.CompareSemver(a, b); err == nil {
		return c
	}
	return version.CompareGeneric(a, b)
}

func cpeVersionMatch(s Subject, subject, criteria []string, a vulndb.Affected) (bool, bool, []string) {
	v := s.Version
	if v == "" && concreteCPE(subject[3]) {
		v = subject[3]
	}
	if !concreteCPE(v) {
		return false, false, nil
	}
	if concreteCPE(subject[3]) && compareCPE(v, subject[3]) != 0 {
		return false, false, nil
	}
	exact := concreteCPE(criteria[3])
	if criteria[3] != "*" && (!exact || v != criteria[3]) {
		return false, false, nil
	}
	if lower, _ := a.Database["versionStartExcluding"].(string); lower != "" && compareCPE(v, lower) <= 0 {
		return false, false, nil
	}
	if len(a.Ranges) == 0 {
		for _, candidate := range a.Versions {
			if v == candidate {
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

func cpeAttributesMatch(s Subject, subject, criteria []string) bool {
	if subject[0] != criteria[0] || subject[1] != criteria[1] || subject[2] != criteria[2] {
		return false
	}
	for i := 4; i < len(criteria); i++ {
		if criteria[i] == "*" {
			continue
		}
		if strings.ContainsAny(criteria[i], "*?") {
			return false
		}
		if criteria[i] == subject[i] {
			continue
		}
		// target_sw may describe a known ecosystem even when the inventory CPE
		// omitted it. Never infer hardware, edition, language, or update attributes.
		if i == 8 && concreteCPE(criteria[i]) && (strings.EqualFold(criteria[i], s.Ecosystem) || strings.EqualFold(criteria[i], s.PURL.Type)) {
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
			records, err = contextual.LookupCPEContext(ctx, attrs[1], attrs[2])
		} else {
			records, err = reader.LookupCPE(attrs[1], attrs[2])
		}
		if err != nil {
			return fmt.Errorf("CPE lookup %s:%s: %w", attrs[1], attrs[2], err)
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
				if a.Ecosystem != "CPE" || a.Package != attrs[1]+":"+attrs[2] {
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
				criteria, ok := vulndb.CPEAttributes(raw)
				if !ok || !concreteCPE(criteria[1]) || !concreteCPE(criteria[2]) || !cpeAttributesMatch(s, attrs, criteria) {
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
