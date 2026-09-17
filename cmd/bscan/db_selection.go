package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type dbAdditionList []string

func (v *dbAdditionList) String() string { return strings.Join(*v, ",") }

func (v *dbAdditionList) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
		if parts[i] == "" || strings.ContainsAny(parts[i], `/\?#`) {
			return fmt.Errorf("invalid addition %q: values must be nonempty and contain none of /, \\, ?, #", part)
		}
	}
	*v = append(*v, parts...)
	return nil
}

type dbSelectionAdditions struct {
	sources, ecosystems, releases dbAdditionList
}

// Resolve each selection field separately. Limits and mirror settings are not
// selection inputs. applyDBDefaults does not mark configured flags as explicit.
func resolveDBSelection(fs *flag.FlagSet, cfg config.DBConfig, old vulndb.Meta, additions dbSelectionAdditions) (vulndb.Selection, string, error) {
	s := old.EffectiveSelection()
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	origins := map[string]bool{}
	base := "defaults"
	if old.SchemaVersion != 0 || old.Selection != nil {
		base = "installed catalog"
	}
	choose := func(name, configured string) (string, bool) {
		if explicit[name] {
			origins["flags"] = true
			return fs.Lookup(name).Value.String(), true
		}
		if configured != "" {
			origins["config"] = true
			return configured, true
		}
		origins[base] = true
		return "", false
	}
	if value, ok := choose("source", strings.Join(cfg.Sources, ",")); ok {
		s.Sources = vulndb.ExpandSelectionList(splitCSV(value), vulndb.DefaultSources)
	}
	if value, ok := choose("ecosystem", strings.Join(cfg.Ecosystems, ",")); ok {
		s.Ecosystems = vulndb.ExpandSelectionList(splitCSV(value), vulndb.DefaultOSVEcosystems)
	}
	if value, ok := choose("alpine-release", strings.Join(cfg.AlpineReleases, ",")); ok {
		s.AlpineReleases = vulndb.ExpandSelectionList(splitCSV(value), vulndb.DefaultAlpineReleases)
	}
	if value, ok := choose("nvd-years", cfg.NVDYears); ok {
		s.NVDYears = value
	}
	s.Sources = append(s.Sources, additions.sources...)
	s.Ecosystems = append(s.Ecosystems, additions.ecosystems...)
	var err error
	s.Ecosystems, err = vulndb.NormalizeOSVEcosystems(s.Ecosystems, func(message string) { logf("db", "%s\n", message) })
	if err != nil {
		return s, "", err
	}
	s.AlpineReleases = append(s.AlpineReleases, additions.releases...)
	s, err = s.Normalize()
	if err != nil {
		return s, "", err
	}
	for _, implied := range []struct {
		flag, source string
		values       dbAdditionList
	}{
		{"--add-ecosystem", "osv", additions.ecosystems},
		{"--add-alpine-release", "alpine", additions.releases},
	} {
		source := vulndb.CanonicalSource(implied.source)
		if len(implied.values) == 0 || slices.Contains(s.Sources, source) {
			continue
		}
		s.Sources = append(s.Sources, source)
		note := ""
		if explicit["source"] {
			note = " (not included in explicit --source)"
		}
		logf("db", "selection: adding source %s for %s%s\n", implied.source, implied.flag, note)
	}
	var provenance []string
	for _, origin := range []string{"flags", "config", "installed catalog", "defaults"} {
		if origins[origin] {
			provenance = append(provenance, origin)
		}
	}
	for _, addition := range []struct {
		name   string
		values dbAdditionList
	}{{"--add-source", additions.sources}, {"--add-ecosystem", additions.ecosystems}, {"--add-alpine-release", additions.releases}} {
		if len(addition.values) > 0 {
			provenance = append(provenance, addition.name)
		}
	}
	return s, strings.Join(provenance, " + "), err
}
