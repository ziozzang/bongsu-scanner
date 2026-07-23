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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	hashutil "github.com/ziozzang/bongsu-scanner/internal/hash"
	"github.com/ziozzang/bongsu-scanner/internal/sbom"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/scramble"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

var version = "dev"

const (
	author     = "ziozzang@gmail.com"
	projectURL = "https://github.com/ziozzang/bongsu-scanner"
)

func main() {
	refreshUpdateCache(os.Args[1:])
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bscan:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
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
	case "hash":
		return cmdHash(args[1:])
	case "sign":
		return cmdSign(args[1:])
	case "check":
		return cmdCheck(ctx, args[1:])
	case "scramble", "encrypt", "decrypt":
		return cmdScramble(args)
	case "batch":
		return cmdBatch(ctx, args[1:])
	case "update", "self-update":
		return cmdUpdate(ctx, args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "about":
		fmt.Printf("bscan %s\nAuthor: %s\nGitHub: %s\n", version, author, projectURL)
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
  bscan init [--signer NAME]
  bscan key show|generate|trust NAME PUBLIC_KEY
  bscan scan [--format both|spdx|cyclonedx] [--output DIR] [--sign] [--verbose] TARGET
  bscan hash [-o FILE.sha256] FILE...
  bscan sign [-o FILE.sig] FILE
  bscan check [--pubkey NAME|FILE|HEX] [--source TARGET] FILE.sha256|FILE.sig
  bscan scramble encrypt [-o FILE.bgs] [--chunk-size 1MiB] FILE
  bscan scramble decrypt [-o FILE] [--pubkey NAME|FILE|HEX] FILE.bgs
  bscan batch [scan flags] TARGET...
  bscan update [--check] [--force]
  bscan about

Targets: host://, docker://IMAGE, container://CONTAINER, directory, tar, tar.gz, tgz

Local examples:
  bscan scan .
  bscan scan --verbose --output ./scan-results /path/to/rootfs
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	signerName := fs.String("signer", "", "signer label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, path, err := config.Load()
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
	cfg, _, err := config.Load()
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
	format, output string
	sign, files    bool
	verbose        bool
}

func addScanFlags(fs *flag.FlagSet) *scanFlags {
	f := &scanFlags{}
	fs.StringVar(&f.format, "format", "both", "spdx, cyclonedx, or both")
	fs.StringVar(&f.output, "output", ".", "output directory")
	fs.BoolVar(&f.sign, "sign", false, "sign SBOMs, or the SHA manifest for a local archive")
	fs.BoolVar(&f.files, "files", true, "include individual file hashes")
	fs.BoolVar(&f.verbose, "verbose", false, "show files, layers, and catalog progress")
	fs.BoolVar(&f.verbose, "v", false, "show verbose scan progress")
	fs.BoolVar(&f.verbose, "V", false, "show verbose scan progress")
	return f
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	f := addScanFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("scan requires exactly one target")
	}
	_, err := scanOne(ctx, fs.Arg(0), *f)
	return err
}

func scanOne(ctx context.Context, target string, f scanFlags) ([]string, error) {
	if target == "host" || target == "host://" {
		f.files = false
	}
	logProgress := func(event scan.Progress) {
		if event.Detail && !f.verbose {
			return
		}
		fmt.Fprintf(os.Stderr, "[scan:%s] %s\n", event.Stage, event.Message)
	}
	fmt.Fprintf(os.Stderr, "[scan:start] target=%s format=%s output=%s file-hashes=%t sign=%t\n",
		target, f.format, f.output, f.files, f.sign)
	r, err := scan.Target(ctx, target, scan.Options{
		IncludeFileHashes: f.files,
		Now:               time.Now(),
		Verbose:           f.verbose,
		Progress:          logProgress,
	})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.output, 0o755); err != nil {
		return nil, err
	}
	base := safeName(r.Name)
	var outputs []string
	formats := []string{f.format}
	if f.format == "both" {
		formats = []string{"spdx", "cyclonedx"}
	}
	for _, format := range formats {
		suffix := map[string]string{"spdx": ".spdx.json", "cyclonedx": ".cdx.json"}[format]
		if suffix == "" {
			return nil, fmt.Errorf("unsupported format %q", format)
		}
		out := filepath.Join(f.output, base+suffix)
		fmt.Fprintf(os.Stderr, "[scan:sbom] writing %s -> %s\n", format, out)
		if err := sbom.Write(out, format, r); err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
	}
	if isPhysicalArchive(r) {
		fmt.Fprintln(os.Stderr, "[scan:policy] local archive: generating source/SBOM SHA-256 manifest")
		if len(r.Layers) > 0 {
			layerPath := filepath.Join(f.output, base+".layers.sha256")
			fmt.Fprintf(os.Stderr, "[scan:hash] writing %d layer digests -> %s\n", len(r.Layers), layerPath)
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
		fmt.Fprintf(os.Stderr, "[scan:hash] writing artifact manifest -> %s\n", manifest)
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
			fmt.Fprintf(os.Stderr, "[scan:sign] signing archive manifest %s\n", manifest)
			sig, err := signPath(manifest, "")
			if err != nil {
				return nil, err
			}
			outputs = append(outputs, sig)
		}
	} else {
		fmt.Fprintln(os.Stderr, "[scan:policy] non-archive target: SBOM only; no SHA manifest")
		if f.sign {
			sbomOutputs := append([]string(nil), outputs...)
			for _, out := range sbomOutputs {
				fmt.Fprintf(os.Stderr, "[scan:sign] signing SBOM %s\n", out)
				sig, err := signPath(out, "")
				if err != nil {
					return nil, err
				}
				outputs = append(outputs, sig)
			}
		}
	}
	fmt.Printf("scan complete: %s (%d packages, %d files, %d layers)\n", target, len(r.Packages), len(r.Files), len(r.Layers))
	for _, out := range outputs {
		fmt.Println(out)
	}
	return outputs, nil
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
	cfg, _, err := config.Load()
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

func cmdCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	pubSpec := fs.String("pubkey", "", "trusted name, public key file, or hex")
	source := fs.String("source", "", "source archive/image for layer manifest verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("check requires one manifest or signature")
	}
	p := fs.Arg(0)
	if strings.HasSuffix(p, ".sig") {
		cfg, _, err := config.Load()
		if err != nil {
			return err
		}
		r, err := sign.ReadRecord(p)
		if err != nil {
			return err
		}
		var pub ed25519.PublicKey
		if *pubSpec != "" {
			pub, err = resolvePublic(cfg, *pubSpec)
			if err != nil {
				return err
			}
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
		fmt.Printf("OK: signature and content verified (%s)\n", r.Signer)
		return nil
	}
	if strings.HasSuffix(p, ".layers.sha256") {
		expected, err := hashutil.Read(p)
		if err != nil {
			return err
		}
		if *source == "" {
			candidate := strings.TrimSuffix(p, ".layers.sha256")
			if _, err := os.Stat(candidate); err == nil {
				*source = candidate
			}
		}
		if *source == "" {
			return errors.New("layer verification requires --source ARCHIVE|docker://IMAGE|container://ID")
		}
		r, err := scan.Target(ctx, *source, scan.Options{IncludeFileHashes: false})
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
		fmt.Println("OK: layer checksums verified")
		return nil
	}
	if err := hashutil.Verify(p); err != nil {
		return err
	}
	fmt.Println("OK: checksums verified")
	return nil
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
	cfg, _, err := config.Load()
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
	cfg, _, err := config.Load()
	if err != nil {
		return err
	}
	if *jobs <= 0 {
		*jobs = cfg.Concurrency
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan string)
	errs := make(chan error, len(fs.Args()))
	var wg sync.WaitGroup
	for range *jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range work {
				if _, err := scanOne(ctx, target, *f); err != nil {
					errs <- fmt.Errorf("%s: %w", target, err)
				}
			}
		}()
	}
	for _, target := range fs.Args() {
		work <- target
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
