package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/report"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type scanMatchFlags struct {
	cpe                           bool
	match                         bool
	reports, db, isolation        string
	minimum, fail                 string
	severitySource                string
	onlyFixed, excludeUnimportant bool
}

func addScanMatchFlags(fs *flag.FlagSet, f *scanMatchFlags) {
	fs.BoolVar(&f.cpe, "cpe", false, "enable conservative NVD CPE matching (CPE data can be noisy)")
	fs.BoolVar(&f.match, "match", false, "match written SBOMs against the local vulnerability database")
	fs.StringVar(&f.reports, "report", "", "comma-separated html, markdown, csv, or sarif reports (requires --match)")
	fs.StringVar(&f.db, "db", "", "local vulnerability database directory (default configured db directory)")
	fs.StringVar(&f.isolation, "db-isolation", "auto", "SQLite reader isolation: auto, copy, or none")
	fs.StringVar(&f.severitySource, "severity-source", "distro", "severity policy: cvss, distro, or max")
	fs.StringVar(&f.minimum, "min-severity", "", "minimum severity to include")
	fs.StringVar(&f.fail, "fail-on", "", "exit with the findings exit code (default 2, see --findings-exit-code) when a finding meets this severity")
	fs.BoolVar(&f.onlyFixed, "only-fixed", false, "include only findings with a known fix")
	addDeprecatedIncludeUnimportant(fs)
	fs.BoolVar(&f.excludeUnimportant, "exclude-unimportant", false, "exclude advisories the distribution rates unimportant or negligible")
}

func applyMatchDefaults(fs *flag.FlagSet, cfg config.MatchConfig) error {
	defaults := map[string]any{
		"severity-source": cfg.SeveritySource, "exclude-unimportant": cfg.ExcludeUnimportant,
		"min-severity": cfg.MinSeverity, "fail-on": cfg.FailOn, "only-fixed": cfg.OnlyFixed,
		"db-isolation": cfg.DBIsolation,
	}
	// Report defaults are meaningful only for the optional scan matching stage.
	if f := fs.Lookup("match"); f != nil && f.Value.String() == "true" {
		defaults["report"] = strings.Join(cfg.ReportFormats, ",")
	}
	return applyFlagDefaults(fs, defaults)
}

type scanMatcher struct {
	store     vulndb.Store
	options   matcher.Options
	formats   []string
	threshold string
}

// Validate and open before scanning, so a missing catalog never triggers a scan.
func prepareScanMatch(ctx context.Context, f scanMatchFlags) (*scanMatcher, error) {
	if !f.match {
		if f.reports != "" {
			return nil, errors.New("--report requires --match")
		}
		return nil, nil
	}
	m := &scanMatcher{}
	seen := make(map[string]bool)
	for _, format := range splitCSV(f.reports) {
		switch format {
		case "html", "markdown", "csv", "sarif":
		default:
			return nil, fmt.Errorf("unsupported report format %q", format)
		}
		if !seen[format] {
			m.formats = append(m.formats, format)
			seen[format] = true
		}
	}
	min, err := severityLevel(f.minimum)
	if err != nil {
		return nil, err
	}
	m.threshold, err = severityLevel(f.fail)
	if err != nil {
		return nil, err
	}
	severityPolicy, err := matcher.NormalizeSeveritySource(f.severitySource)
	if err != nil {
		return nil, err
	}
	m.options = matcher.Options{ToolVersion: version, CPE: f.cpe, SeveritySource: severityPolicy, MinSeverity: min, OnlyFixed: f.onlyFixed, ExcludeUnimportant: f.excludeUnimportant}
	if f.db == "" {
		f.db, err = databaseDir()
		if err != nil {
			return nil, err
		}
	}
	f.db = filepath.Clean(f.db)
	missing := func() error {
		return fmt.Errorf("no vulnerability database at %s; run 'bscan db update'", f.db)
	}
	if _, err := os.Stat(f.db); errors.Is(err, os.ErrNotExist) {
		return nil, missing()
	} else if err != nil {
		return nil, err
	}
	m.store, err = vulndb.OpenWithOptionsContext(ctx, f.db, vulndb.Options{Isolation: f.isolation})
	if errors.Is(err, os.ErrNotExist) {
		return nil, missing()
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Prefer the CycloneDX document actually written for this result. SPDX-only
// scans use their SPDX document; signatures and manifests are never inputs.
func scanMatchSBOM(paths []string) (path, base string, err error) {
	for _, suffix := range []string{".cdx.json", ".spdx.json"} {
		for _, path := range paths {
			if strings.HasSuffix(path, suffix) {
				return path, strings.TrimSuffix(path, suffix), nil
			}
		}
	}
	return "", "", errors.New("scan produced no SBOM to match")
}

func (m *scanMatcher) write(ctx context.Context, sboms []string, reserved *scanOutputPaths, name string) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	input, base, err := scanMatchSBOM(sboms)
	if err != nil {
		return nil, false, err
	}
	doc, err := matcher.LoadFile(input)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", input, err)
	}
	r, err := matcher.Run(ctx, m.store, doc.Subjects, m.options)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", input, err)
	}
	logMissingCoverage("scan:match", r)
	logf("scan:match", "%d subjects, %d findings (critical=%d high=%d)\n",
		r.Subjects, len(r.Findings), r.BySeverity["CRITICAL"], r.BySeverity["HIGH"])
	paths := []string{base + ".findings.json"}
	for _, format := range m.formats {
		ext := format
		if ext == "markdown" {
			ext = "md"
		}
		paths = append(paths, base+".report."+ext)
	}
	if err := reserved.reserve(append([]string(nil), paths...), name); err != nil {
		return nil, false, err
	}
	if err := writeReportFile(paths[0], func(w io.Writer) error {
		return matcher.Write(w, "json", r, doc)
	}); err != nil {
		return nil, false, err
	}
	// Keep the report context and matcher options consistent with cmdMatch.
	in := report.Input{Report: r, Target: filepath.Base(input), SBOMPath: input,
		GeneratedAt: time.Now().UTC(), ToolVersion: version, Options: m.options}
	if len(m.formats) > 0 {
		if target, scan, os, image, host, err := report.ContextFromSBOM(input); err == nil {
			in.Scan, in.OS, in.Image, in.Host = scan, os, image, host
			if target != "" {
				in.Target = target
			}
		}
	}
	for i, format := range m.formats {
		if err := writeReportFile(paths[i+1], func(w io.Writer) error {
			if err := report.Render(w, format, in); err != nil {
				return err
			}
			return ctx.Err()
		}); err != nil {
			return paths[:i+1], false, err
		}
	}
	return paths, m.threshold != "" && matcher.ShouldFail(r, m.threshold), nil
}
