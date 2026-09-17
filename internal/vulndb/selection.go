package vulndb

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Selection records feed inputs, independently of ecosystems found in records.
// An empty NVDYears means the rolling default (current year and previous two).
type Selection struct {
	Sources        []string `json:"sources"`
	Ecosystems     []string `json:"ecosystems"`
	AlpineReleases []string `json:"alpine_releases"`
	NVDYears       string   `json:"nvd_years"`
	NVDEnabled     bool     `json:"nvd_enabled"`
}

// ExpandSelectionList expands default/defaults in place and keeps first entries.
func ExpandSelectionList(values, defaults []string) []string {
	if len(values) == 0 {
		values = defaults
	}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "default" || value == "defaults" {
			out = append(out, defaults...)
		} else {
			out = append(out, value)
		}
	}
	return dedupeStrings(out)
}

// EffectiveSelection supports manifests predating selection metadata. Only OSV
// feed declarations describe the old OSV selection; Meta.Ecosystems does not.
func (m Meta) EffectiveSelection() Selection {
	if m.Selection != nil {
		return m.Selection.withDefaults()
	}
	var s Selection
	for _, feed := range m.Sources {
		if CanonicalSource(feed.Name) == SourceOSV {
			s.Ecosystems = append(s.Ecosystems, feed.Ecosystems...)
		}
	}
	return s.withDefaults()
}

func (s Selection) withDefaults() Selection {
	s.Sources = ExpandSelectionList(s.Sources, DefaultSources)
	for i, name := range s.Sources {
		s.Sources[i] = CanonicalSource(name)
	}
	s.Sources = dedupeStrings(s.Sources)
	s.Ecosystems = ExpandSelectionList(s.Ecosystems, DefaultOSVEcosystems)
	s.AlpineReleases = ExpandSelectionList(s.AlpineReleases, DefaultAlpineReleases)
	s.NVDEnabled = slices.Contains(s.Sources, SourceNVD)
	return s
}

// Normalize expands defaults and validates the NVD year specification. The
// rolling default (empty, or only default tokens) stays empty so that a
// persisted selection keeps following the current year on later updates
// instead of freezing the years that happened to be current when it was
// built. Explicit years are validated and kept as written.
func (s Selection) Normalize() (Selection, error) {
	return s.normalize(time.Now())
}

func (s Selection) normalize(now time.Time) (Selection, error) {
	s = s.withDefaults()
	var defaults []string
	for year := now.UTC().Year() - 2; year <= now.UTC().Year(); year++ {
		defaults = append(defaults, strconv.Itoa(year))
	}
	if s.NVDYears != "" {
		var parts []string
		rolling := true
		for _, part := range strings.Split(s.NVDYears, ",") {
			if token := strings.TrimSpace(part); token == "default" || token == "defaults" {
				parts = append(parts, defaults...)
			} else {
				rolling = false
				// Preserve empty items so the existing NVD parser rejects them.
				parts = append(parts, part)
			}
		}
		if rolling {
			s.NVDYears = ""
		} else {
			s.NVDYears = strings.Join(parts, ",")
		}
	}
	if s.NVDEnabled {
		if _, err := parseNVDYears(s.NVDYears, now); err != nil {
			return s, err
		}
	}
	return s, nil
}

func (s Selection) String() string {
	years := s.NVDYears
	if years == "" {
		years = "default"
	}
	return fmt.Sprintf("sources=%s ecosystems=%s alpine=%s nvd=%t nvd-years=%s",
		strings.Join(s.Sources, ","), strings.Join(s.Ecosystems, ","),
		strings.Join(s.AlpineReleases, ","), s.NVDEnabled, years)
}
