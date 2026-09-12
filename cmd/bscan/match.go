package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	matcher "github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/report"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type findingsError struct{ threshold string }

func (e *findingsError) Error() string { return "vulnerabilities meet --fail-on " + e.threshold }
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var found *findingsError
	if errors.As(err, &found) {
		return 2
	}
	return 1
}

func databaseDir() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "db"), nil
}

func splitCSV(value string) []string {
	var result []string
	for _, s := range strings.Split(value, ",") {
		if s = strings.TrimSpace(s); s != "" {
			result = append(result, s)
		}
	}
	return result
}

func severityLevel(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "", "UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return value, nil
	default:
		return "", fmt.Errorf("invalid severity %q (want UNKNOWN, NEGLIGIBLE, LOW, MEDIUM, HIGH, or CRITICAL)", value)
	}
}

func cmdMatch(ctx context.Context, args []string) (resultErr error) {
	dir, err := databaseDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	cpuProfile := fs.String("cpuprofile", "", "write CPU profile")
	memProfile := fs.String("memprofile", "", "write heap profile")
	fs.Usage = func() {
		visible := flag.NewFlagSet("match", flag.ContinueOnError)
		visible.SetOutput(fs.Output())
		fs.VisitAll(func(f *flag.Flag) {
			if f.Name != "cpuprofile" && f.Name != "memprofile" {
				visible.Var(f.Value, f.Name, f.Usage)
				visible.Lookup(f.Name).DefValue = f.DefValue
			}
		})
		fmt.Fprintln(fs.Output(), "Usage of match:")
		visible.PrintDefaults()
	}
	db := fs.String("db", dir, "local vulnerability database directory")
	isolation := fs.String("db-isolation", "auto", "SQLite reader isolation: auto, copy, or none")
	format := fs.String("format", "table", "table, json, cyclonedx, html, markdown, csv, or sarif")
	out := fs.String("o", "", "output file (default stdout)")
	minimum := fs.String("min-severity", "", "minimum severity to include")
	fail := fs.String("fail-on", "", "exit 2 when a finding meets this severity")
	ignore := fs.String("ignore", "", "comma-separated advisory IDs to ignore")
	unimportant := fs.Bool("include-unimportant", false, "include Debian unimportant advisories")
	details := fs.Bool("details", false, "include full advisory details text in findings")
	fixed := fs.Bool("only-fixed", false, "include only findings with a known fix")
	pub := fs.String("pubkey", "", "require database signature from trusted name, PEM file, or hex key")
	llm := fs.Bool("llm", false, "add LLM environment applicability review; retain original findings")
	llmURL := fs.String("llm-base-url", os.Getenv("BSCAN_LLM_BASE_URL"), "OpenAI-compatible API base URL, e.g. https://server/v1")
	llmModel := fs.String("llm-model", os.Getenv("BSCAN_LLM_MODEL"), "model identifier on the selected LLM server")
	llmKeyEnv := fs.String("llm-key-env", "BSCAN_LLM_API_KEY", "environment variable containing the API key")
	llmTimeout := fs.Duration("llm-timeout", 90*time.Second, "timeout per LLM request")
	llmMax := fs.Int("llm-max-findings", 20, "maximum distinct LLM analyses per input SBOM")
	llmCache := fs.String("llm-cache", filepath.Join(filepath.Dir(dir), "cache", "llm"), "LLM cache directory (empty disables caching)")
	targetOS := fs.String("target-os", "", "LLM context OS override, e.g. linux or windows")
	targetArch := fs.String("target-arch", "", "LLM context architecture override, e.g. amd64")
	facts := map[string]string{}
	fs.Func("env-fact", "user-declared LLM context KEY=VALUE (repeatable)", func(value string) error {
		key, val, ok := strings.Cut(value, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !ok || key == "" || val == "" || len(key) > 64 || len(val) > 1024 || len(facts) >= 32 {
			return errors.New("--env-fact requires a nonempty KEY=VALUE (at most 32 facts, 64-byte keys and 1024-byte values)")
		}
		facts[key] = val
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("match requires at least one SBOM file")
	}
	if *format == "md" {
		*format = "markdown"
	}
	reportFormat := false
	switch *format {
	case "table", "json", "cyclonedx":
	case "html", "markdown", "csv", "sarif":
		reportFormat = true
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}
	if (*format == "cyclonedx" || reportFormat) && fs.NArg() != 1 {
		return fmt.Errorf("%s output requires exactly one SBOM input", *format)
	}
	min, err := severityLevel(*minimum)
	if err != nil {
		return err
	}
	threshold, err := severityLevel(*fail)
	if err != nil {
		return err
	}
	var analyzer assessment.Analyzer
	if *llm {
		cfg, _, err := config.Load()
		if err != nil {
			return err
		}
		if offlineMode(cfg) {
			return errors.New("LLM requests disabled: offline mode; run match without --llm for local database matching")
		}
		if *llmMax < 1 || *llmTimeout <= 0 {
			return errors.New("--llm-max-findings and --llm-timeout must be positive")
		}
		if strings.TrimSpace(*llmURL) == "" || strings.TrimSpace(*llmModel) == "" {
			return errors.New("--llm requires BSCAN_LLM_BASE_URL and BSCAN_LLM_MODEL (or --llm-base-url and --llm-model)")
		}
		analyzer, err = assessment.New(assessment.Config{BaseURL: *llmURL, Model: *llmModel, APIKey: os.Getenv(*llmKeyEnv), CacheDir: *llmCache, Timeout: *llmTimeout})
		if err != nil {
			return err
		}
		analyzer = &loggedAnalyzer{inner: analyzer}
	} else if *targetOS != "" || *targetArch != "" || len(facts) > 0 {
		return errors.New("--target-os, --target-arch and --env-fact require --llm")
	}
	if *cpuProfile != "" {
		f, err := os.OpenFile(*cpuProfile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return err
		}
		defer func() { pprof.StopCPUProfile(); resultErr = errors.Join(resultErr, f.Close()) }()
	}
	if *memProfile != "" {
		f, err := os.OpenFile(*memProfile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { runtime.GC(); resultErr = errors.Join(resultErr, pprof.WriteHeapProfile(f), f.Close()) }()
	}
	*db = filepath.Clean(*db)
	if _, err := os.Stat(*db); os.IsNotExist(err) {
		return fmt.Errorf("no vulnerability database at %s; run 'bscan db update'", *db)
	}
	key, err := dbPublicKey(*pub)
	if err != nil {
		return err
	}
	store, err := vulndb.OpenWithOptionsContext(ctx, *db, vulndb.Options{PublicKey: key, Isolation: *isolation})
	if err != nil {
		return err
	}
	defer store.Close()
	var reports []matcher.Report
	var output bytes.Buffer
	failed := false
	var analysisErrors []error
	for _, input := range fs.Args() {
		if err := ctx.Err(); err != nil {
			return err
		}
		doc, err := matcher.LoadFile(input)
		if err != nil {
			return fmt.Errorf("%s: %w", input, err)
		}
		matchReport, err := matcher.Run(ctx, store, doc.Subjects, matcher.Options{
			Details: *details, IncludeUnimportant: *unimportant, MinSeverity: min, IgnoreIDs: splitCSV(*ignore), OnlyFixed: *fixed,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", input, err)
		}
		fmt.Fprintf(os.Stderr, "[match] %s: db updated %s; %d subjects; %d findings\n", httpx.Sanitize(input), matchReport.DB.UpdatedAt.UTC().Format(time.RFC3339), matchReport.Subjects, len(matchReport.Findings))
		if len(matchReport.Skipped) > 0 {
			fmt.Fprintf(os.Stderr, "[match] skipped: %v\n", matchReport.Skipped)
		}
		if analyzer != nil {
			fmt.Fprintf(os.Stderr, "[match:llm] reviewing up to %d distinct findings with %s\n", *llmMax, httpx.Sanitize(*llmModel))
			err := matcher.Enrich(ctx, &matchReport, doc, analyzer, assessment.Environment{OS: *targetOS, Arch: *targetArch, Facts: facts}, *llmMax)
			if err != nil {
				analysisErrors = append(analysisErrors, fmt.Errorf("LLM review of %s: %w", httpx.Sanitize(input), err))
			}
		}
		if threshold != "" && matcher.ShouldFail(matchReport, threshold) {
			failed = true
		}
		reports = append(reports, matchReport)
		if *format == "json" && fs.NArg() > 1 {
			continue
		}
		if *format == "table" && fs.NArg() > 1 {
			fmt.Fprintf(&output, "\n%s\n", httpx.Sanitize(input))
		}
		if reportFormat {
			in := report.Input{Report: matchReport, Target: filepath.Base(input), SBOMPath: input, GeneratedAt: time.Now().UTC(), ToolVersion: version,
				Options: matcher.Options{Details: *details, IncludeUnimportant: *unimportant, MinSeverity: min, IgnoreIDs: splitCSV(*ignore), OnlyFixed: *fixed}}
			if target, scanMeta, osMeta, image, host, err := report.ContextFromSBOM(input); err == nil {
				in.Scan, in.OS, in.Image, in.Host = scanMeta, osMeta, image, host
				if target != "" {
					in.Target = target
				}
			}
			if err := report.Render(&output, *format, in); err != nil {
				return err
			}
			continue
		}
		if err := matcher.Write(&output, *format, matchReport, doc); err != nil {
			return err
		}
	}
	if *format == "json" && fs.NArg() > 1 {
		enc := json.NewEncoder(&output)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	}
	if err := writeCommandOutput(*out, output.Bytes()); err != nil {
		return err
	}
	if failed {
		analysisErrors = append(analysisErrors, &findingsError{threshold: threshold})
	}
	return errors.Join(analysisErrors...)
}

// Prepare the complete output before replacing a file, including when an
// input SBOM is also the output path. Failed rendering preserves the input.
func writeCommandOutput(path string, data []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		// Devices, pipes and sockets (e.g. /dev/null) cannot be replaced by
		// rename; write through them directly.
		return os.WriteFile(path, data, 0o644)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bscan-output-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = io.Copy(f, bytes.NewReader(data)); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Show per-advisory progress without logging API credentials or request bodies.
type loggedAnalyzer struct {
	inner assessment.Analyzer
	count int
}

func (a *loggedAnalyzer) Analyze(ctx context.Context, input assessment.Input) (assessment.Result, error) {
	a.count++
	fmt.Fprintf(os.Stderr, "[match:llm] %d: %s (%s %s)\n", a.count, httpx.Sanitize(input.AdvisoryID), httpx.Sanitize(input.Package), httpx.Sanitize(input.Version))
	result, err := a.inner.Analyze(ctx, input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[match:llm] analysis unavailable; original finding retained")
	} else {
		fmt.Fprintf(os.Stderr, "[match:llm] %s (cached=%t)\n", result.Status, result.Cached)
	}
	return result, err
}
