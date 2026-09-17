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
	for _, typ := range []string{"CVSS_V3", "CVSS_V2"} {
		best := -1.0
		vector := ""
		for _, s := range severities {
			if s.Type != typ {
				continue
			}
			if n, e := cvss(s.Score); e == nil && n > best {
				best, vector = n, s.Score
			}
		}
		if best >= 0 {
			return scoreSeverity(best), best, vector
		}
	}
	vector := ""
	level := "UNKNOWN"
	for _, s := range severities {
		if s.Type == "CVSS_V4" {
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
