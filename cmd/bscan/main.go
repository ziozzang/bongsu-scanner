// CLI output contract: stdout contains primary results (including scan complete
// lines and artifact paths). Progress, warnings and operational summaries use
// the stderr logging shim; quiet suppresses logs and JSON changes only logs.
// Terminating errors are returned to the single top-level stderr printer.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	hashutil "github.com/ziozzang/bongsu-scanner/internal/hash"
	"github.com/ziozzang/bongsu-scanner/internal/sbom"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/scramble"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

var (
	version   = "dev"
	commit    string
	buildDate string
)

const (
	author     = "ziozzang@gmail.com"
	projectURL = "https://github.com/ziozzang/bongsu-scanner"
)

func main() {
	// SIGINT/SIGTERM cancel the context so docker child processes are killed
	// and temporary docker save/export tars are removed by their defers. A
	// second signal after cancellation falls back to the default handler.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// One line, no stack of wrapped causes: the operator pressed Ctrl-C.
			fmt.Fprintln(os.Stderr, "bscan: interrupted")
		} else {
			fmt.Fprintln(os.Stderr, "bscan:", err)
		}
		os.Exit(exitCode(err))
	}
}

// partialScanError is returned by --fail-on-partial; it maps to exit code 3
// so CI can distinguish an incomplete inventory from a hard failure (1) and
// from findings above the --fail-on threshold (2).
type partialScanError struct {
	target                  string
	denied, errors, skipped int
	limit                   string
}

func (e *partialScanError) Error() string {
	return fmt.Sprintf("partial scan of %s (denied=%d errors=%d metadata-skipped=%d limit=%q): --fail-on-partial", e.target, e.denied, e.errors, e.skipped, e.limit)
}

func run(ctx context.Context, args []string) (err error) {
	defer func() {
		if errors.Is(err, flag.ErrHelp) {
			err = nil
		}
	}()
	options, rest, err := parseGlobalFlags(args)
	if err != nil {
		return err
	}
	restore, err := applyGlobalFlags(options)
	if err != nil {
		return err
	}
	defer restore()
	args = rest
	if err := validateConfigOverride(); err != nil {
		return err
	}
	if !options.quiet && options.logFormat == "text" && len(args) > 0 && args[0] != "completion" {
		refreshUpdateCache(args)
	}
	if printCommandHelp(args) {
		return nil
	}
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "key":
		return cmdKey(args[1:])
	case "scan":
		return cmdScan(ctx, args[1:])
	case "db":
		return cmdDB(ctx, args[1:])
	case "match":
		return cmdMatch(ctx, args[1:])
	case "report":
		return cmdReport(ctx, args[1:])
	case "hash":
		return cmdHash(args[1:])
	case "sign":
		return cmdSign(args[1:])
	case "check":
		return cmdCheck(ctx, args[1:], false)
	case "verify":
		return cmdCheck(ctx, args[1:], true)
	case "scramble", "encrypt", "decrypt":
		return cmdScramble(args)
	case "batch":
		return cmdBatch(ctx, args[1:])
	case "update", "self-update":
		return cmdUpdate(ctx, args[1:])
	case "completion":
		return cmdCompletion(args[1:])
	case "version", "--version", "-v":
		printVersion()
		return nil
	case "about":
		printVersion()
		fmt.Printf("Author: %s\nGitHub: %s\nLicense: MIT (LICENSE)\nThird-party notices: THIRD_PARTY_NOTICES.txt\n", author, projectURL)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Print(`bscan - embedded host/container SBOM scanner and artifact signer

Usage:
  bscan [global flags] COMMAND [command flags] [arguments]

Global flags (before COMMAND):
  -q, --quiet          suppress progress logs on stderr
  --log-format FORMAT text (default) or json
  --no-color          compatibility placeholder (no color is emitted)
  --config PATH       override BONGSU_CONFIG and the default config path
  --version, -v       show build information

Commands:
  bscan init [--signer NAME]
  bscan key show|generate|trust NAME PUBLIC_KEY
  bscan scan [--format both|spdx|cyclonedx] [--output DIR] [--sign|--no-sign] [--verbose]
             [--exclude PATH]... [--no-default-excludes] [--one-file-system] [--max-files N]
             [--timeout DURATION] [--no-host-metadata] [--redact-ip] [--containers]
             [--skip-binaries] [--workers N] [--platform os/arch] [--allow-digest-mismatch] [--fail-on-partial] TARGET
  bscan hash [-o FILE.sha256] FILE...
  bscan sign [-o FILE.sig] FILE
  bscan verify [--pubkey NAME|FILE|HEX] FILE.sig [FILE.sig...]
  bscan check [--pubkey NAME|FILE|HEX] [--source TARGET] FILE.sha256|FILE.sig [...]
  bscan scramble encrypt [-o FILE.bgs] [--chunk-size 1MiB] FILE
  bscan scramble decrypt [-o FILE] [--pubkey NAME|FILE|HEX] FILE.bgs
  bscan batch [scan flags] TARGET...
  bscan db update|status|lookup|show|verify|export|import|convert [options]
  bscan match [--db DIR] [--format table|json|cyclonedx|html|markdown|csv|sarif] [--fail-on LEVEL] [--llm] SBOM...
  bscan report --from MATCH.json [--sbom SBOM.json] [--format html|markdown|json|csv|sarif] [-o FILE] [--title TEXT]
  bscan update [--check] [--force] [--require-signature]
  bscan version|about
  bscan completion bash|zsh|fish
  bscan help [COMMAND [SUBCOMMAND]]

Targets: host, docker://IMAGE, container://CONTAINER, directory, tar, tar.gz, tgz

Local examples:
  bscan scan .
  bscan scan --sign --output ./host-scan host
  bscan scan --containers --redact-ip --timeout 30m --output ./host-scan host
  bscan scan --verbose --output ./scan-results /path/to/rootfs
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	signerName := fs.String("signer", "", "signer label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, path, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	if *signerName != "" {
		cfg.Signer = *signerName
	}
	priv, keyPath, created, err := ensureKey(&cfg)
	if err != nil {
		return err
	}
	cfg.PrivateKey = keyPath
	if cfg.PublicKey == "" {
		d, _ := config.Dir()
		cfg.PublicKey = filepath.Join(d, "signing.pub")
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("config: %s\nprivate key: %s (created=%t)\nfingerprint: %s\n", path, keyPath, created, sign.Fingerprint(priv.Public().(ed25519.PublicKey)))
	return nil
}

func cmdKey(args []string) error {
	if len(args) == 0 {
		return errors.New("key requires show, generate, or trust")
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	switch args[0] {
	case "generate":
		_, _, _, err := ensureKey(&cfg)
		if err == nil {
			err = config.Save(cfg)
		}
		return err
	case "show":
		priv, path, _, err := ensureKey(&cfg)
		if err != nil {
			return err
		}
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("private: %s\npublic: %s\nfingerprint: %s\n", path, hex.EncodeToString(pub), sign.Fingerprint(pub))
		return nil
	case "trust":
		if len(args) != 3 {
			return errors.New("usage: bscan key trust NAME PUBLIC_KEY")
		}
		pub, err := resolvePublic(cfg, args[2])
		if err != nil {
			return err
		}
		cfg.TrustedKeys[args[1]] = hex.EncodeToString(pub)
		return config.Save(cfg)
	default:
		return fmt.Errorf("unknown key command %q", args[0])
	}
}

type scanFlags struct {
	scanMatchFlags
	format, output string
	sign, noSign   bool
	files          bool
	verbose        bool
	autoSigner     string

	batchOutputBase string
	hostContainers  bool
	outputPaths     *scanOutputPaths

	exclude             []string
	noDefaultExcludes   bool
	oneFileSystem       bool
	maxFiles            int64
	timeout             time.Duration
	noHostMetadata      bool
	redactIP            bool
	containers          bool
	skipBinaries        bool
	workers             int
	platform            string
	allowDigestMismatch bool
	failOnPartial       bool
}

func addScanFlags(fs *flag.FlagSet) *scanFlags {
	f := &scanFlags{}
	addScanMatchFlags(fs, &f.scanMatchFlags)
	fs.StringVar(&f.format, "format", "both", "spdx, cyclonedx, or both")
	fs.StringVar(&f.output, "output", ".", "output directory")
	fs.BoolVar(&f.sign, "sign", false, "sign SBOMs, or the SHA manifest for a local archive")
	fs.BoolVar(&f.noSign, "no-sign", false, "disable signing even when a configured key is available")
	fs.BoolVar(&f.files, "files", true, "include individual file hashes")
	fs.BoolVar(&f.verbose, "verbose", false, "show files, layers, and catalog progress")
	fs.BoolVar(&f.verbose, "v", false, "show verbose scan progress")
	fs.BoolVar(&f.verbose, "V", false, "show verbose scan progress")
	fs.Func("exclude", "path or glob to skip (repeatable; absolute, root-relative, or bare name)", func(v string) error {
		f.exclude = append(f.exclude, v)
		return nil
	})
	fs.BoolVar(&f.noDefaultExcludes, "no-default-excludes", false, "walk /proc, /var/lib/docker, caches, ... during host scans")
	fs.BoolVar(&f.oneFileSystem, "one-file-system", false, "do not cross mount points below the scan root")
	fs.Int64Var(&f.maxFiles, "max-files", 0, "stop the directory walk after N regular files (0 = unlimited)")
	fs.DurationVar(&f.timeout, "timeout", 0, "abort the scan after this duration (e.g. 10m; 0 = none)")
	fs.BoolVar(&f.noHostMetadata, "no-host-metadata", false, "omit hostname, hardware and IP details from host SBOMs")
	fs.BoolVar(&f.redactIP, "redact-ip", false, "omit IP addresses from host metadata")
	fs.BoolVar(&f.containers, "containers", false, "after a host scan, also scan every running Docker container into its own SBOM")
	fs.BoolVar(&f.skipBinaries, "skip-binaries", false, "do not extract Go build info from ELF executables")
	fs.IntVar(&f.workers, "workers", 0, "directories walked concurrently for host/directory scans (0 = min(8, CPUs), 1 = sequential)")
	fs.StringVar(&f.platform, "platform", "", "image platform to select from multi-arch archives, os/arch[/variant]")
	fs.BoolVar(&f.allowDigestMismatch, "allow-digest-mismatch", false, "record mismatching layer digests instead of failing")
	fs.BoolVar(&f.failOnPartial, "fail-on-partial", false, "exit with an error when a walk was partial (permission denied, I/O errors, limits)")
	return f
}

func (f scanFlags) options() scan.Options {
	return scan.Options{
		IncludeFileHashes:   f.files,
		Now:                 time.Now(),
		Verbose:             f.verbose,
		Platform:            f.platform,
		AllowDigestMismatch: f.allowDigestMismatch,
		Exclude:             f.exclude,
		NoDefaultExcludes:   f.noDefaultExcludes,
		OneFileSystem:       f.oneFileSystem,
		MaxFiles:            f.maxFiles,
		NoHostMetadata:      f.noHostMetadata,
		RedactIPs:           f.redactIP,
		IncludeContainers:   f.containers,
		SkipBinaries:        f.skipBinaries,
		Workers:             f.workers,
	}
}

// outputBase names the SBOM files for one result: "host" for the host,
// "host.container-NAME" for containers scanned alongside it.
func outputBase(r scan.Result, f scanFlags) string {
	base := f.batchOutputBase
	if base == "" {
		base = safeName(r.Name)
	}
	if f.hostContainers && r.SourceType == "container" {
		if f.batchOutputBase == "" {
			base = "host"
		}
		return base + ".container-" + safeName(strings.TrimPrefix(r.Name, "host:container:"))
	}
	return base
}

// scanOutputPaths reserves final paths across all results and batch workers.
type scanOutputPaths struct {
	mu    sync.Mutex
	paths map[string]string
}

func (p *scanOutputPaths) reserve(paths []string, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.paths == nil {
		p.paths = make(map[string]string)
	}
	for i, path := range paths {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		paths[i] = abs
		if previous, ok := p.paths[abs]; ok {
			return fmt.Errorf("output path collision: %q and %q both write %s", previous, name, abs)
		}
	}
	for _, path := range paths {
		p.paths[path] = name
	}
	return nil
}

func cmdScan(ctx context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	f := addScanFlags(fs)
	cpuProfile := fs.String("cpuprofile", "", "")
	memProfile := fs.String("memprofile", "", "")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage of scan:")
		visible := flag.NewFlagSet("scan", flag.ContinueOnError)
		visible.SetOutput(fs.Output())
		addScanFlags(visible)
		visible.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("scan requires exactly one target")
	}
	if *cpuProfile != "" {
		out, createErr := os.Create(*cpuProfile)
		if createErr != nil {
			return createErr
		}
		if startErr := pprof.StartCPUProfile(out); startErr != nil {
			out.Close()
			return startErr
		}
		defer func() {
			pprof.StopCPUProfile()
			err = errors.Join(err, out.Close())
		}()
	}
	if *memProfile != "" {
		out, createErr := os.Create(*memProfile)
		if createErr != nil {
			return createErr
		}
		defer func() {
			err = errors.Join(err, pprof.WriteHeapProfile(out), out.Close())
		}()
	}
	_, err = scanOne(ctx, fs.Arg(0), *f)
	return err
}

func scanOne(ctx context.Context, target string, f scanFlags) ([]string, error) {
	if f.format != "both" && f.format != "spdx" && f.format != "cyclonedx" {
		return nil, fmt.Errorf("unsupported format %q", f.format)
	}
	if f.maxFiles < 0 || f.timeout < 0 {
		return nil, errors.New("--max-files and --timeout must not be negative")
	}
	matching, err := prepareScanMatch(ctx, f.scanMatchFlags)
	if err != nil {
		return nil, err
	}
	if matching != nil {
		defer matching.store.Close()
	}
	if err := resolveScanSigning(&f); err != nil {
		return nil, err
	}
	if scan.IsHostTarget(target) {
		f.files = false
	}
	f.hostContainers = scan.IsHostTarget(target) && f.containers
	if f.outputPaths == nil {
		f.outputPaths = &scanOutputPaths{}
	}
	if f.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}
	logProgress := func(event scan.Progress) {
		if event.Detail && !f.verbose {
			return
		}
		logf("scan:"+event.Stage, "%s\n", event.Message)
	}
	logf("scan:start", "target=%s format=%s output=%s file-hashes=%t sign=%t\n",
		target, f.format, f.output, f.files, f.sign)
	switch {
	case f.noSign:
		logf("scan:sign", "%s\n", "signing explicitly disabled (--no-sign)")
	case f.autoSigner != "":
		logf("scan:sign", "auto-sign enabled: signer=%s\n", f.autoSigner)
	case f.sign:
		logf("scan:sign", "%s\n", "signing explicitly enabled (--sign)")
	default:
		logf("scan:sign", "%s\n", "unsigned scan: configured signer/private key not available")
	}
	opts := f.options()
	opts.Progress = logProgress
	results, scanErr := scan.TargetAll(ctx, target, opts)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
		return nil, scanErr
	}
	if len(results) == 0 {
		if scanErr == nil {
			scanErr = errors.New("scan produced no result")
		}
		return nil, scanErr
	}
	if scanErr != nil {
		logf("scan:policy", "warning: %v\n", scanErr)
	}
	for _, r := range results {
		if r.Scan == nil || !r.Scan.Partial {
			continue
		}
		logf("scan:policy", "partial scan of %s (denied=%d errors=%d metadata-skipped=%d limit=%q); SBOM will be marked partial\n",
			r.Name, r.Scan.PermissionDenied, r.Scan.SkippedErrors, r.Scan.MetadataSkipped, r.Scan.LimitReached)
		if f.failOnPartial {
			return nil, &partialScanError{target: r.Name, denied: r.Scan.PermissionDenied, errors: r.Scan.SkippedErrors, skipped: r.Scan.MetadataSkipped, limit: r.Scan.LimitReached}
		}
	}
	if err := os.MkdirAll(f.output, 0o755); err != nil {
		return nil, err
	}
	var outputs []string
	failed := false
	for _, r := range results {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		written, err := writeScanOutputs(r, f)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, written...)
		if matching != nil {
			paths, meetsThreshold, err := matching.write(ctx, written, f.outputPaths, r.Name)
			outputs = append(outputs, paths...)
			if err != nil {
				return outputs, err
			}
			failed = failed || meetsThreshold
		}
		scanSummaryf("scan complete: %s (%d packages, %d files, %d layers)\n", r.Name, len(r.Packages), len(r.Files), len(r.Layers))
	}
	for _, out := range outputs {
		fmt.Println(out)
	}
	if failed {
		scanErr = errors.Join(scanErr, &findingsError{threshold: matching.threshold})
	}
	return outputs, scanErr
}

// writeScanOutputs writes and (optionally) signs the SBOMs and manifests
// for one scan result, returning the created paths.
func writeScanOutputs(r scan.Result, f scanFlags) ([]string, error) {
	base := outputBase(r, f)
	var outputs []string
	formats := []string{f.format}
	if f.format == "both" {
		formats = []string{"spdx", "cyclonedx"}
	}
	var sbomPaths, reserved []string
	archive := isPhysicalArchive(r)
	for _, format := range formats {
		suffix := map[string]string{"spdx": ".spdx.json", "cyclonedx": ".cdx.json"}[format]
		if suffix == "" {
			return nil, fmt.Errorf("unsupported format %q", format)
		}
		out := filepath.Join(f.output, base+suffix)
		sbomPaths = append(sbomPaths, out)
		reserved = append(reserved, out)
		if f.sign && !archive {
			reserved = append(reserved, out+".sig")
		}
	}
	if archive {
		if len(r.Layers) > 0 {
			reserved = append(reserved, filepath.Join(f.output, base+".layers.sha256"))
		}
		manifest := filepath.Join(f.output, base+".sha256")
		reserved = append(reserved, manifest)
		if f.sign {
			reserved = append(reserved, manifest+".sig")
		}
	}
	if f.outputPaths == nil {
		f.outputPaths = &scanOutputPaths{}
	}
	if err := f.outputPaths.reserve(reserved, r.Name); err != nil {
		return nil, err
	}
	for i, format := range formats {
		out := sbomPaths[i]
		logf("scan:sbom", "writing %s -> %s\n", format, out)
		if err := sbom.Write(out, format, r); err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
	}
	if archive {
		logf("scan:policy", "%s\n", "local archive: generating source/SBOM SHA-256 manifest")
		if len(r.Layers) > 0 {
			layerPath := filepath.Join(f.output, base+".layers.sha256")
			logf("scan:hash", "writing %d layer digests -> %s\n", len(r.Layers), layerPath)
			var entries []hashutil.Entry
			for _, l := range r.Layers {
				entries = append(entries, hashutil.Entry{Digest: l.SHA256, Path: l.Path})
			}
			if err := hashutil.Write(layerPath, entries); err != nil {
				return nil, err
			}
			outputs = append(outputs, layerPath)
		}
		manifest := filepath.Join(f.output, base+".sha256")
		logf("scan:hash", "writing artifact manifest -> %s\n", manifest)
		var entries []hashutil.Entry
		for _, out := range outputs {
			d, err := hashutil.File(out)
			if err != nil {
				return nil, err
			}
			entries = append(entries, hashutil.Entry{Digest: d, Path: filepath.Base(out)})
		}
		sourcePath, relErr := filepath.Rel(f.output, r.Source)
		if relErr != nil {
			sourcePath = r.Source
		}
		entries = append(entries, hashutil.Entry{Digest: r.SourceHash, Path: filepath.ToSlash(sourcePath)})
		if err := hashutil.Write(manifest, entries); err != nil {
			return nil, err
		}
		outputs = append(outputs, manifest)
		if f.sign {
			logf("scan:sign", "signing archive manifest %s\n", manifest)
			sig, err := signPath(manifest, "")
			if err != nil {
				return nil, err
			}
			outputs = append(outputs, sig)
		}
	} else {
		logf("scan:policy", "%s\n", "non-archive target: SBOM only; no SHA manifest")
		if f.sign {
			sbomOutputs := append([]string(nil), outputs...)
			for _, out := range sbomOutputs {
				logf("scan:sign", "signing SBOM %s\n", out)
				sig, err := signPath(out, "")
				if err != nil {
					return nil, err
				}
				outputs = append(outputs, sig)
			}
		}
	}
	return outputs, nil
}

func resolveScanSigning(f *scanFlags) error {
	if f.sign && f.noSign {
		return errors.New("--sign and --no-sign cannot be used together")
	}
	if f.noSign {
		f.sign = false
		return nil
	}
	if f.sign {
		return nil
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return fmt.Errorf("load signing config: %w", err)
	}
	if strings.TrimSpace(cfg.Signer) == "" {
		return nil
	}
	keyPath, err := config.Expand(cfg.PrivateKey)
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read configured signing key: %w", err)
	}
	if _, err := sign.ParsePrivate(keyData); err != nil {
		return fmt.Errorf("configured signing key is invalid: %w", err)
	}
	f.sign = true
	f.autoSigner = cfg.Signer
	return nil
}

func isPhysicalArchive(r scan.Result) bool {
	switch r.SourceType {
	case "archive", "docker-archive", "oci-archive":
	default:
		return false
	}
	info, err := os.Stat(r.Source)
	return err == nil && info.Mode().IsRegular()
}

func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	out := fs.String("o", "", "manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("hash requires files")
	}
	if *out == "" {
		*out = fs.Arg(0) + ".sha256"
	}
	var entries []hashutil.Entry
	for _, p := range fs.Args() {
		d, err := hashutil.File(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Dir(*out), p)
		if err != nil {
			rel = p
		}
		entries = append(entries, hashutil.Entry{Digest: d, Path: filepath.ToSlash(rel)})
	}
	if err := hashutil.Write(*out, entries); err != nil {
		return err
	}
	fmt.Println(*out)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	out := fs.String("o", "", "signature path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("sign requires one file")
	}
	p, err := signPath(fs.Arg(0), *out)
	if err == nil {
		fmt.Println(p)
	}
	return err
}

func signPath(target, output string) (string, error) {
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return "", err
	}
	priv, _, _, err := ensureKey(&cfg)
	if err != nil {
		return "", err
	}
	digest, err := hashutil.File(target)
	if err != nil {
		return "", err
	}
	r, err := sign.Create(digest, filepath.Base(target), cfg.Signer, priv, time.Now())
	if err != nil {
		return "", err
	}
	if output == "" {
		output = target + ".sig"
	}
	return output, sign.WriteRecord(output, r)
}

func cmdCheck(ctx context.Context, args []string, requireTrusted bool) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	pubSpec := fs.String("pubkey", "", "trusted name, public key file, or hex")
	source := fs.String("source", "", "source archive/image for layer manifest verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("check requires one or more manifests or signatures")
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	var failures []error
	for _, p := range fs.Args() {
		if err := checkOne(ctx, p, *pubSpec, *source, cfg, requireTrusted); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", p, err))
		}
	}
	return errors.Join(failures...)
}

func checkOne(ctx context.Context, p, pubSpec, source string, cfg config.Config, requireTrusted bool) error {
	if strings.HasSuffix(p, ".sig") {
		r, err := sign.ReadRecord(p)
		if err != nil {
			return err
		}
		if err := cfg.CheckSignatureVersion(r.Version); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		pub, trust, err := verificationKey(cfg, r, pubSpec, requireTrusted)
		if err != nil {
			return err
		}
		if err := r.Verify(pub); err != nil {
			return err
		}
		target := r.Target
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(p), target)
		}
		got, err := hashutil.File(target)
		if err != nil {
			return err
		}
		if got != r.DigestSHA256 {
			return errors.New("signed target checksum mismatch")
		}
		if strings.HasSuffix(target, ".sha256") {
			if err := hashutil.Verify(target); err != nil {
				return err
			}
		}
		signer := r.Signer
		if !r.Authenticated() {
			signer += " (unauthenticated: v1 record)"
		}
		fmt.Printf("OK: %s: signature, target digest, and content verified (signer=%s, trust=%s, signed=%s)\n",
			p, signer, trust, r.SignedAt.UTC().Format(time.RFC3339))
		return nil
	}
	if strings.HasSuffix(p, ".layers.sha256") {
		expected, err := hashutil.Read(p)
		if err != nil {
			return err
		}
		if source == "" {
			candidate := strings.TrimSuffix(p, ".layers.sha256")
			if _, err := os.Stat(candidate); err == nil {
				source = candidate
			}
		}
		if source == "" {
			return errors.New("layer verification requires --source ARCHIVE|docker://IMAGE|container://ID")
		}
		r, err := scan.Target(ctx, source, scan.Options{IncludeFileHashes: false})
		if err != nil {
			return err
		}
		if len(expected) != len(r.Layers) {
			return fmt.Errorf("layer count mismatch: got %d, want %d", len(r.Layers), len(expected))
		}
		for i, layer := range r.Layers {
			if expected[i].Digest != layer.SHA256 || expected[i].Path != layer.Path {
				return fmt.Errorf("layer %d mismatch (%s)", i, layer.Path)
			}
		}
		fmt.Printf("OK: %s: layer checksums verified\n", p)
		return nil
	}
	if err := hashutil.Verify(p); err != nil {
		return err
	}
	fmt.Printf("OK: %s: checksums verified\n", p)
	return nil
}

func verificationKey(cfg config.Config, record sign.Record, spec string, requireTrusted bool) (ed25519.PublicKey, string, error) {
	if spec != "" {
		pub, err := resolvePublic(cfg, spec)
		if err != nil {
			return nil, "", err
		}
		return pub, "pinned:" + spec, nil
	}
	embedded, err := sign.ParsePublic([]byte(record.PublicKey))
	if err != nil {
		return nil, "", err
	}
	for name, value := range cfg.TrustedKeys {
		pub, err := sign.ParsePublic([]byte(value))
		if err == nil && pub.Equal(embedded) {
			return pub, "trusted:" + name, nil
		}
	}
	publicPath := cfg.PublicKey
	if publicPath == "" {
		if dir, err := config.Dir(); err == nil {
			publicPath = filepath.Join(dir, "signing.pub")
		}
	}
	if publicPath != "" {
		if pub, err := resolvePublic(cfg, publicPath); err == nil && pub.Equal(embedded) {
			return pub, "local:" + publicPath, nil
		}
	}
	if requireTrusted {
		return nil, "", errors.New("signature key is not trusted; use --pubkey KEY or 'bscan key trust NAME KEY'")
	}
	return nil, "embedded-unpinned", nil
}

func cmdScramble(args []string) error {
	if args[0] == "encrypt" || args[0] == "decrypt" {
		args = append([]string{"scramble"}, args...)
	}
	if len(args) < 2 {
		return errors.New("scramble requires encrypt or decrypt")
	}
	mode := args[1]
	fs := flag.NewFlagSet("scramble "+mode, flag.ContinueOnError)
	out := fs.String("o", "", "output path")
	chunk := fs.String("chunk-size", "1MiB", "processing chunk size")
	pubSpec := fs.String("pubkey", "", "pinned public key for decryption")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("scramble requires one input file")
	}
	inPath := fs.Arg(0)
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	switch mode {
	case "encrypt":
		if *out == "" {
			*out = inPath + ".bgs"
		}
		info, err := in.Stat()
		if err != nil {
			return err
		}
		n, err := parseSize(*chunk)
		if err != nil {
			return err
		}
		priv, _, _, err := ensureKey(&cfg)
		if err != nil {
			return err
		}
		return atomicOutput(*out, func(w *os.File) error {
			return scramble.Encrypt(in, w, uint64(info.Size()), n, priv, time.Now())
		})
	case "decrypt":
		if *out == "" {
			*out = strings.TrimSuffix(inPath, ".bgs") + ".plain"
		}
		var pub ed25519.PublicKey
		if *pubSpec != "" {
			pub, err = resolvePublic(cfg, *pubSpec)
			if err != nil {
				return err
			}
		} else if cfg.PublicKey != "" {
			pub, _ = resolvePublic(cfg, cfg.PublicKey)
		}
		return atomicOutput(*out, func(w *os.File) error {
			_, err := scramble.Decrypt(in, w, pub)
			return err
		})
	default:
		return fmt.Errorf("unknown scramble mode %q", mode)
	}
}

func cmdBatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	f := addScanFlags(fs)
	jobs := fs.Int("jobs", 0, "parallel scans")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("batch requires targets")
	}
	bases, err := batchOutputBases(fs.Args())
	if err != nil {
		return err
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	if *jobs <= 0 {
		*jobs = cfg.Concurrency
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f.outputPaths = &scanOutputPaths{}
	work := make(chan int)
	errs := make(chan error, len(fs.Args()))
	var wg sync.WaitGroup
	for range *jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				target := fs.Arg(i)
				flags := *f
				flags.batchOutputBase = bases[i]
				if _, err := scanOne(ctx, target, flags); err != nil {
					errs <- fmt.Errorf("%s: %w", target, err)
				}
			}
		}()
	}
	for i := range fs.Args() {
		work <- i
	}
	close(work)
	wg.Wait()
	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	return errors.Join(all...)
}

// batchOutputBases reserves names before workers can write any output.
func batchOutputBases(targets []string) ([]string, error) {
	bases := make([]string, len(targets))
	paths := make(map[string]string, len(targets))
	counts := make(map[string]int, len(targets))
	for i, target := range targets {
		var identity, name string
		switch {
		case scan.IsHostTarget(target):
			identity, name = "path:/", "host"
		case strings.HasPrefix(target, "docker://"), strings.HasPrefix(target, "container://"):
			identity = target
			_, name, _ = strings.Cut(target, "://")
		default:
			abs, err := filepath.Abs(target)
			if err != nil {
				return nil, fmt.Errorf("resolve batch target %q: %w", target, err)
			}
			resolved, err := filepath.EvalSymlinks(abs)
			if err != nil {
				resolved = abs
			}
			identity, name = "path:"+resolved, filepath.Base(target)
			if info, err := os.Stat(target); err == nil && info.IsDir() {
				name = filepath.Base(resolved)
			}
		}
		if previous, ok := paths[identity]; ok {
			return nil, fmt.Errorf("duplicate target: %q and %q resolve to %s", previous, target, strings.TrimPrefix(identity, "path:"))
		}
		paths[identity] = target
		bases[i] = safeName(name)
		counts[bases[i]]++
	}
	// Reserve original names too, so a suffix cannot overwrite another target
	// whose basename already contains that suffix (for example rootfs-1).
	used := make(map[string]bool, len(counts))
	for base := range counts {
		used[base] = true
	}
	for i, base := range bases {
		if counts[base] < 2 {
			continue
		}
		for suffix := i + 1; ; suffix++ {
			candidate := fmt.Sprintf("%s-%d", base, suffix)
			if used[candidate] {
				continue
			}
			bases[i] = candidate
			used[candidate] = true
			logf("batch:collision", "target=%s output base %s -> %s\n", targets[i], base, candidate)
			break
		}
	}
	return bases, nil
}

func ensureKey(cfg *config.Config) (ed25519.PrivateKey, string, bool, error) {
	path, err := config.Expand(cfg.PrivateKey)
	if err != nil {
		return nil, "", false, err
	}
	if b, err := os.ReadFile(path); err == nil {
		priv, err := sign.ParsePrivate(b)
		return priv, path, false, err
	} else if !os.IsNotExist(err) {
		return nil, path, false, err
	}
	pub, priv, err := sign.Generate()
	if err != nil {
		return nil, path, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, path, false, err
	}
	pem, err := sign.MarshalPrivate(priv)
	if err != nil {
		return nil, path, false, err
	}
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return nil, path, false, err
	}
	d, _ := config.Dir()
	pubPath := cfg.PublicKey
	if pubPath == "" {
		pubPath = filepath.Join(d, "signing.pub")
	}
	pubPath, _ = config.Expand(pubPath)
	pubPEM, _ := sign.MarshalPublic(pub)
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return nil, path, false, err
	}
	cfg.PrivateKey, cfg.PublicKey = path, pubPath
	return priv, path, true, nil
}

func resolvePublic(cfg config.Config, spec string) (ed25519.PublicKey, error) {
	if v, ok := cfg.TrustedKeys[spec]; ok {
		spec = v
	}
	if p, err := config.Expand(spec); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			return sign.ParsePublic(b)
		}
	}
	if b, err := os.ReadFile(spec); err == nil {
		return sign.ParsePublic(b)
	}
	return sign.ParsePublic([]byte(spec))
}

func safeName(s string) string {
	s = filepath.Base(strings.TrimSuffix(s, "/"))
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "scan"
	}
	return b.String()
}

func parseSize(s string) (int, error) {
	units := map[string]int64{"": 1, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "kb": 1000, "mb": 1000000, "gb": 1000000000}
	lower := strings.ToLower(strings.TrimSpace(s))
	for unit, mult := range units {
		if strings.HasSuffix(lower, unit) {
			raw := strings.TrimSpace(strings.TrimSuffix(lower, unit))
			if raw == "" {
				continue
			}
			n, err := strconv.ParseInt(raw, 10, 64)
			if err == nil && n > 0 && n*mult <= 1<<30 {
				return int(n * mult), nil
			}
		}
	}
	return 0, fmt.Errorf("invalid size %q", s)
}

func atomicOutput(path string, fn func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}

// Keep JSON linked into the binary for future machine-readable batch records.
var _ = json.Valid

// Linker overrides remain compatible with make build's -X main.version.
func buildIdentity(info *debug.BuildInfo) (string, string, string, string, string) {
	v, revision, date, goVersion, module := version, commit, buildDate, runtime.Version(), "github.com/ziozzang/bongsu-scanner"
	modified := false
	if info != nil {
		if info.GoVersion != "" {
			goVersion = info.GoVersion
		}
		if info.Main.Path != "" {
			module = info.Main.Path
		}
		if (v == "" || v == "dev") && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if commit == "" {
					revision = setting.Value
				}
			case "vcs.time":
				if buildDate == "" {
					date = setting.Value
				}
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	if revision == "" {
		revision = "unknown"
	}
	if modified && commit == "" {
		revision += " (modified)"
	}
	if date == "" {
		date = "unknown"
	}
	return v, revision, date, goVersion, module
}

func printVersion() {
	info, _ := debug.ReadBuildInfo()
	v, revision, date, goVersion, module := buildIdentity(info)
	fmt.Printf("bscan %s\nCommit: %s\nBuild date: %s\nGo: %s\nPlatform: %s/%s\nModule: %s\n",
		v, revision, date, goVersion, runtime.GOOS, runtime.GOARCH, module)
}

type globalFlags struct {
	quiet, noColor, showVersion bool
	logFormat, configPath       string
}

func globalFlagSet(options *globalFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("bscan", flag.ContinueOnError)
	fs.BoolVar(&options.quiet, "q", false, "suppress progress logs on stderr")
	fs.BoolVar(&options.quiet, "quiet", false, "suppress progress logs on stderr")
	fs.StringVar(&options.logFormat, "log-format", "text", "progress/summary log format: text or json")
	fs.BoolVar(&options.noColor, "no-color", false, "compatibility placeholder; output never uses color")
	fs.StringVar(&options.configPath, "config", "", "configuration path (overrides BONGSU_CONFIG)")
	fs.BoolVar(&options.showVersion, "version", false, "show build information")
	fs.BoolVar(&options.showVersion, "v", false, "show build information")
	fs.Usage = usage
	return fs
}

func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	var options globalFlags
	fs := globalFlagSet(&options)
	if err := fs.Parse(args); err != nil {
		return options, nil, err
	}
	if options.logFormat != "text" && options.logFormat != "json" {
		return options, nil, fmt.Errorf("--log-format must be text or json, got %q", options.logFormat)
	}
	var emptyConfig bool
	fs.Visit(func(f *flag.Flag) {
		emptyConfig = emptyConfig || (f.Name == "config" && strings.TrimSpace(f.Value.String()) == "")
	})
	if emptyConfig {
		return options, nil, errors.New("--config requires a nonempty path")
	}
	if options.showVersion {
		return options, []string{"version"}, nil
	}
	return options, fs.Args(), nil
}

var progressLog struct {
	sync.Mutex
	quiet bool
	json  bool
}

// applyGlobalFlags runs before config consumers, including background updates.
// Restoring the environment also makes repeated in-process invocations safe.
func applyGlobalFlags(options globalFlags) (func(), error) {
	previousConfig, hadConfig := os.LookupEnv("BONGSU_CONFIG")
	if options.configPath != "" {
		if err := os.Setenv("BONGSU_CONFIG", options.configPath); err != nil {
			return nil, err
		}
	}
	progressLog.Lock()
	previousQuiet, previousJSON := progressLog.quiet, progressLog.json
	progressLog.quiet, progressLog.json = options.quiet, options.logFormat == "json"
	progressLog.Unlock()
	return func() {
		progressLog.Lock()
		progressLog.quiet, progressLog.json = previousQuiet, previousJSON
		progressLog.Unlock()
		if options.configPath != "" {
			if hadConfig {
				_ = os.Setenv("BONGSU_CONFIG", previousConfig)
			} else {
				_ = os.Unsetenv("BONGSU_CONFIG")
			}
		}
	}, nil
}

// logf is shared by commands. Keep each event atomic across batch workers.
// Errors returned by commands are reported separately and never suppressed.
func logf(stage, format string, args ...any) {
	writeLogf("info", stage, format, args...)
}

func warnf(stage, format string, args ...any) {
	writeLogf("warn", stage, format, args...)
}

// logWriter adapts helpers that emit complete diagnostic lines to the shim.
type logWriter struct {
	stage   string
	warning bool
}

func (w logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimSuffix(string(p), "\n"), "\n") {
		line = strings.TrimPrefix(line, "["+w.stage+"] ")
		if w.warning {
			warnf(w.stage, "%s", line)
		} else {
			logf(w.stage, "%s", line)
		}
	}
	return len(p), nil
}

func writeLogf(level, stage, format string, args ...any) {
	progressLog.Lock()
	defer progressLog.Unlock()
	if progressLog.quiet {
		return
	}
	message := fmt.Sprintf(format, args...)
	if progressLog.json {
		_ = json.NewEncoder(os.Stderr).Encode(struct {
			TS    string `json:"ts"`
			Level string `json:"level"`
			Stage string `json:"stage"`
			Msg   string `json:"msg"`
		}{time.Now().UTC().Format(time.RFC3339Nano), level, stage, strings.TrimSuffix(message, "\n")})
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s", stage, message)
	if !strings.HasSuffix(message, "\n") {
		fmt.Fprintln(os.Stderr)
	}
}

func scanSummaryf(format string, args ...any) {
	fmt.Printf(format, args...)
}

// Config path resolution belongs to internal/config. Until that package honors
// BONGSU_CONFIG, reject an unmatched override rather than silently using another
// file (which could bypass a requested offline or signature policy).
func validateConfigOverride() error {
	requested := strings.TrimSpace(os.Getenv("BONGSU_CONFIG"))
	if requested == "" {
		return nil
	}
	actual, err := config.Path()
	if err != nil {
		return err
	}
	requested, err = filepath.Abs(requested)
	if err != nil {
		return err
	}
	actual, err = filepath.Abs(actual)
	if err != nil {
		return err
	}
	if actual != requested {
		return errors.New("configuration override unavailable: internal/config must support BONGSU_CONFIG before --config can select a different file")
	}
	return nil
}
