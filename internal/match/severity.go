package match

import (
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"math"
	"strconv"
	"strings"
)

// CVSSBase computes the base score only. Formulas and Roundup follow FIRST:
// https://www.first.org/cvss/v3-1/specification-document (7 and Appendix A)
// https://www.first.org/cvss/v2/guide (3.2.1).
// V4 intentionally returns an error: it requires the official lookup algorithm.
func CVSSBase(vector string) (float64, error) {
	vector = strings.TrimSpace(vector)
	m := map[string]string{}
	for _, seg := range strings.Split(strings.Trim(vector, "()"), "/") {
		k, v, ok := strings.Cut(seg, ":")
		if !ok {
			return 0, fmt.Errorf("invalid CVSS metric %q", seg)
		}
		if _, dup := m[k]; dup {
			return 0, fmt.Errorf("duplicate CVSS metric %s", k)
		}
		m[k] = v
	}
	get := func(k string, values map[string]float64) (float64, error) {
		v, ok := values[m[k]]
		if !ok {
			return 0, fmt.Errorf("invalid or missing CVSS metric %s", k)
		}
		return v, nil
	}
	if strings.HasPrefix(vector, "CVSS:3.0/") || strings.HasPrefix(vector, "CVSS:3.1/") {
		if m["S"] != "U" && m["S"] != "C" {
			return 0, fmt.Errorf("invalid scope")
		}
		pr := map[string]float64{"N": .85, "L": .62, "H": .27}
		if m["S"] == "C" {
			pr = map[string]float64{"N": .85, "L": .68, "H": .5}
		}
		weights := []struct {
			k string
			v map[string]float64
		}{{"AV", map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2}}, {"AC", map[string]float64{"L": .77, "H": .44}}, {"PR", pr}, {"UI", map[string]float64{"N": .85, "R": .62}}, {"C", map[string]float64{"N": 0, "L": .22, "H": .56}}, {"I", map[string]float64{"N": 0, "L": .22, "H": .56}}, {"A", map[string]float64{"N": 0, "L": .22, "H": .56}}}
		w := []float64{}
		for _, x := range weights {
			v, e := get(x.k, x.v)
			if e != nil {
				return 0, e
			}
			w = append(w, v)
		}
		iss := 1 - (1-w[4])*(1-w[5])*(1-w[6])
		impact := 6.42 * iss
		if m["S"] == "C" {
			impact = 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
		}
		if impact <= 0 {
			return 0, nil
		}
		score := impact + 8.22*w[0]*w[1]*w[2]*w[3]
		if m["S"] == "C" {
			score *= 1.08
		}
		score = math.Min(score, 10)
		n := math.Round(score * 100000)
		if math.Mod(n, 10000) == 0 {
			return n / 100000, nil
		}
		return (math.Floor(n/10000) + 1) / 10, nil
	}
	if m["CVSS"] != "" && m["CVSS"] != "2.0" {
		return 0, fmt.Errorf("unsupported CVSS version %q", m["CVSS"])
	}
	weights := []struct {
		k string
		v map[string]float64
	}{{"AV", map[string]float64{"N": 1, "A": .646, "L": .395}}, {"AC", map[string]float64{"L": .71, "M": .61, "H": .35}}, {"Au", map[string]float64{"N": .704, "S": .56, "M": .45}}, {"C", map[string]float64{"N": 0, "P": .275, "C": .66}}, {"I", map[string]float64{"N": 0, "P": .275, "C": .66}}, {"A", map[string]float64{"N": 0, "P": .275, "C": .66}}}
	w := []float64{}
	for _, x := range weights {
		v, e := get(x.k, x.v)
		if e != nil {
			return 0, e
		}
		w = append(w, v)
	}
	impact := 10.41 * (1 - (1-w[3])*(1-w[4])*(1-w[5]))
	if impact == 0 {
		return 0, nil
	}
	score := (.6*impact + .4*20*w[0]*w[1]*w[2] - 1.5) * 1.176
	return math.Round(score*10) / 10, nil
}
func scoreSeverity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NEGLIGIBLE"
	}
}
func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH", "IMPORTANT":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "NEGLIGIBLE", "UNIMPORTANT", "NONE", "INFO":
		return "NEGLIGIBLE"
	default:
		return "UNKNOWN"
	}
}

type cvssResult struct {
	score float64
	err   error
}

func (c *versionCache) cvssBase(vector string) (float64, error) {
	if result, ok := c.cvss[vector]; ok {
		return result.score, result.err
	}
	score, err := CVSSBase(vector)
	// A Run sees many advisories with the same vectors. Bound both entry count
	// and individual key length so malformed feed data cannot pin large text.
	if len(vector) <= 1024 {
		if len(c.cvss) >= 1024 {
			clear(c.cvss)
		}
		c.cvss[vector] = cvssResult{score, err}
	}
	return score, err
}
func (c *versionCache) severity(rec vulndb.Record, a vulndb.Affected) (string, float64, string) {
	return severityWithCVSS(rec, a, c.cvssBase)
}
func severity(rec vulndb.Record, a vulndb.Affected) (string, float64, string) {
	return severityWithCVSS(rec, a, CVSSBase)
}
func severityWithCVSS(rec vulndb.Record, a vulndb.Affected, cvss func(string) (float64, error)) (string, float64, string) {
	severities := a.Severity
	if len(severities) == 0 {
		severities = rec.Severity
	}
	for _, typ := range []string{"CVSS_V4", "CVSS_V3", "CVSS_V2"} {
		best := -1.0
		vector := ""
		for _, s := range severities {
			if s.Type != typ {
				continue
			}
			// Scores published without a vector participate in the same maximum.
			if n, e := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); e == nil {
				if n >= 0 && n <= 10 && n > best {
					best, vector = n, ""
				}
				continue
			}
			if typ != "CVSS_V4" {
				if n, e := cvss(s.Score); e == nil && n > best {
					best, vector = n, s.Score
				}
			}
		}
		if best >= 0 {
			return scoreSeverity(best), best, vector
		}
	}
	vector := ""
	level := "UNKNOWN"
	for _, s := range severities {
		if s.Type == "CVSS_V4" && strings.HasPrefix(s.Score, "CVSS:4.0/") {
			vector = s.Score
		}
		if n, e := strconv.ParseFloat(s.Score, 64); e == nil && n >= 0 && n <= 10 && s.Type != "CVSS_V4" {
			return scoreSeverity(n), n, vector
		}
		if l := normalizeSeverity(s.Score); SeverityRank(l) > SeverityRank(level) {
			level = l
		}
	}
	for _, database := range []map[string]any{rec.Database, a.Database} {
		for _, key := range []string{"severity", "urgency"} {
			if l := normalizeSeverity(fmt.Sprint(database[key])); SeverityRank(l) > SeverityRank(level) {
				level = l
			}
		}
	}
	return level, 0, vector
}

// Package/release urgency takes precedence over record-wide urgency. Preserve
// non-ranked values (for example end-of-life) for presentation, not scoring.
func distroSeverity(rec vulndb.Record, a vulndb.Affected) string {
	if vulndb.BaseEcosystem(a.Ecosystem) == "Red Hat" {
		for _, database := range []map[string]any{a.Database, rec.Database} {
			if label, ok := database["severity"].(string); ok {
				if level := normalizeSeverity(label); level != "UNKNOWN" {
					return strings.ToLower(level)
				}
			}
		}
	}
	if vulndb.BaseEcosystem(a.Ecosystem) == "Ubuntu" {
		// Ubuntu publishes package priority in exports and record priority in
		// API responses. Both are more specific than generic urgency metadata.
		for _, key := range []string{"ubuntu_priority", "priority"} {
			if priority, ok := a.Specific[key].(string); ok && strings.TrimSpace(priority) != "" {
				return strings.ToLower(strings.TrimSpace(priority))
			}
		}
		for _, rating := range rec.Severity {
			if rating.Type == "Ubuntu" && strings.TrimSpace(rating.Score) != "" {
				return strings.ToLower(strings.TrimSpace(rating.Score))
			}
		}
	}
	for _, database := range []map[string]any{a.Database, a.Specific, rec.Database} {
		if urgency, ok := database["urgency"].(string); ok && strings.TrimSpace(urgency) != "" {
			return strings.ToLower(strings.TrimSpace(urgency))
		}
	}
	for _, prefix := range []string{"RLSA-", "ALSA-", "RHSA-", "USN-", "DSA-", "DLA-"} {
		if strings.HasPrefix(rec.ID, prefix) {
			// Prefer the vendor's textual rating over aggregate CVSS scores.
			if label, ok := rec.Database["severity"].(string); ok {
				if level := normalizeSeverity(label); level != "UNKNOWN" {
					return strings.ToLower(level)
				}
			}
			for _, rating := range rec.Severity {
				if level := normalizeSeverity(rating.Score); level != "UNKNOWN" {
					return strings.ToLower(level)
				}
			}
			// AlmaLinux and Rocky publish vendor ratings at the start of
			// erratum titles, independently of their CVEs' CVSS scores.
			if label, _, ok := strings.Cut(rec.Summary, ":"); ok {
				switch strings.ToLower(label) {
				case "critical", "important", "moderate", "low":
					return strings.ToLower(normalizeSeverity(label))
				}
			}
			// With no separate vendor label, retain the erratum's rating.
			// Multiple CVE aliases still remain one advisory finding.
			sev, _, _ := severity(rec, vulndb.Affected{})
			if sev != "UNKNOWN" {
				return strings.ToLower(sev)
			}
			break
		}
	}
	return ""
}

// NormalizeSeveritySource validates the policy for both CLI entry points and Run.
func NormalizeSeveritySource(source string) (string, error) {
	switch source {
	case "":
		return "distro", nil
	case "cvss", "distro", "max":
		return source, nil
	default:
		return "", fmt.Errorf("invalid severity source %q (want cvss, distro, or max)", source)
	}
}

func selectedSeverity(cvss, distro, source string) string {
	level := distroSeverityLevel(distro)
	if level != "UNKNOWN" && (source == "distro" || source == "max" && SeverityRank(level) > SeverityRank(cvss)) {
		return level
	}
	return cvss
}

func mergeDistroSeverity(a, b string) string {
	if a == "unimportant" || b == "unimportant" {
		return "unimportant"
	}
	if a == "negligible" || b == "negligible" {
		return "negligible"
	}
	if a == "" || SeverityRank(distroSeverityLevel(b)) > SeverityRank(distroSeverityLevel(a)) {
		return b
	}
	return a
}

// distroSeverityLevel recognizes vendor urgency without changing CVSS parsing.
func distroSeverityLevel(urgency string) string {
	if strings.EqualFold(strings.TrimSpace(urgency), "emergency") {
		return "CRITICAL"
	}
	return normalizeSeverity(urgency)
}

// SeverityPolicy describes the selected policy for output legends.
func SeverityPolicy(source string) string {
	switch source {
	case "", "distro":
		return "Severity policy: distro (vendor rating first, CVSS fallback)"
	case "cvss":
		return "Severity policy: cvss (CVSS rating)"
	case "max":
		return "Severity policy: max (higher of vendor rating and CVSS)"
	default:
		return "Severity policy: unknown"
	}
}
