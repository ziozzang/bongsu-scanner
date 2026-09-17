package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/purl"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func dbPublicKey(spec string) (ed25519.PublicKey, error) {
	if spec == "" {
		return nil, nil
	}
	cfg, _, err := config.Load()
	if err != nil {
		return nil, err
	}
	return resolvePublic(cfg, spec)
}

func cmdDB(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("db requires update, status, lookup, show, verify, export, import, or convert")
	}
	dir, err := databaseDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("db "+args[0], flag.ContinueOnError)
	db := fs.String("db", dir, "database directory")
	if args[0] == "update" {
		return cmdDBUpdate(ctx, fs, db, args[1:])
	}
	isolation := fs.String("db-isolation", "auto", "SQLite reader isolation: auto, copy, or none")
	pub := fs.String("pubkey", "", "require signature from trusted name, PEM file, or hex key")
	var noRaw bool
	if args[0] == "convert" {
		fs.BoolVar(&noRaw, "no-keep-raw", false, "omit original downloads from converted database")
	}
	if err := parseCommandFlags(fs, args[1:]); err != nil {
		return err
	}
	*db = filepath.Clean(*db)
	key, err := dbPublicKey(*pub)
	if err != nil {
		return err
	}
	switch args[0] {
	case "convert":
		if fs.NArg() != 1 {
			return errors.New("db convert requires a destination directory; --db selects the source")
		}
		cfg, _, err := config.LoadForCLI()
		if err != nil {
			return err
		}
		if err := applyDBDefaults(fs, cfg.DB); err != nil {
			return err
		}
		opts := vulndb.Options{PublicKey: key, NoKeepRaw: noRaw}
		if err := setDBSigning(cfg, &opts); err != nil {
			return err
		}
		meta, err := vulndb.Convert(ctx, *db, filepath.Clean(fs.Arg(0)), opts)
		if err != nil {
			return err
		}
		fmt.Printf("SQLite database: %s\n", filepath.Join(fs.Arg(0), vulndb.SQLiteFileName))
		return printDBMetaTo(logWriter{stage: "db"}, meta)
	case "import":
		if fs.NArg() != 1 {
			return errors.New("db import requires one tar.gz archive")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		meta, err := vulndb.ImportContext(ctx, fs.Arg(0), *db, key)
		if err != nil {
			return err
		}
		fmt.Println(*db)
		return printDBMetaTo(logWriter{stage: "db"}, meta)
	case "export":
		if fs.NArg() != 1 {
			return errors.New("db export requires one tar.gz output path")
		}
		if err := waitForCatalog(ctx, 10*time.Second, func() error {
			return vulndb.ExportVerified(*db, fs.Arg(0), key)
		}); err != nil {
			return err
		}
		fmt.Println(fs.Arg(0))
		return nil
	case "verify":
		if fs.NArg() != 0 {
			return errors.New("db verify takes no positional arguments")
		}
		// Resolve trust after recovery under the verification generation's lock.
		var store vulndb.Store
		err := waitForCatalog(ctx, 10*time.Second, func() error {
			var openErr error
			store, openErr = vulndb.OpenWithKeyResolverContext(ctx, *db, vulndb.Options{PublicKey: key, Isolation: *isolation}, func(dir string) (ed25519.PublicKey, error) {
				if *pub != "" {
					return key, nil
				}
				record, err := vulndb.ReadSignatureContext(ctx, filepath.Join(dir, "manifest.sha256.sig"))
				if os.IsNotExist(err) {
					return nil, nil
				}
				if err != nil {
					return nil, err
				}
				cfg, _, err := config.Load()
				if err != nil {
					return nil, err
				}
				key, _, err = verificationKey(cfg, record, "", true)
				return key, err
			})
			return openErr
		})
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		if key == nil {
			fmt.Println("OK: database checksums verified (unsigned)")
		} else {
			fmt.Println("OK: database checksums and trusted signature verified")
		}
		return nil
	case "status", "lookup", "show":
		if args[0] == "status" && fs.NArg() != 0 {
			return errors.New("db status takes no positional arguments")
		}
		if args[0] == "show" && fs.NArg() != 1 {
			return errors.New("db show requires one advisory ID or alias")
		}
		if args[0] == "lookup" && fs.NArg() != 2 {
			return errors.New("db lookup requires ECOSYSTEM NAME")
		}
		var store vulndb.Store
		open := func() error {
			var err error
			store, err = vulndb.OpenWithOptionsContext(ctx, *db, vulndb.Options{PublicKey: key, Isolation: *isolation})
			return err
		}
		var err error
		if args[0] == "status" {
			err = waitForCatalog(ctx, 10*time.Second, open)
		} else {
			err = open()
		}
		if err != nil {
			return err
		}
		defer store.Close()
		if args[0] == "lookup" || args[0] == "show" {
			var records []vulndb.Record
			var err error
			if args[0] == "show" {
				records, err = vulndb.LookupIDContext(ctx, store, fs.Arg(0))
			} else {
				records, err = vulndb.LookupContext(ctx, store, fs.Arg(0), fs.Arg(1))
				records = filterDBLookupRelease(records, fs.Arg(0), fs.Arg(1))
			}
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(records)
		}
		meta, err := store.Meta()
		if err != nil {
			return err
		}
		if err := printDBMeta(meta); err != nil {
			return err
		}
		var size int64
		err = filepath.WalkDir(*db, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type().IsRegular() {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				size += info.Size()
			}
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("Disk size: %s\n", vulndb.FormatBytes(size))
		if _, err := os.Stat(filepath.Join(*db, "manifest.sha256.sig")); err == nil {
			fmt.Println("Signature: valid; use 'db verify --pubkey KEY' to pin provenance")
		} else {
			fmt.Println("Signature: unsigned (checksums verified)")
		}
		return nil
	default:
		return fmt.Errorf("unknown db command %q", args[0])
	}
}

func filterDBLookupRelease(records []vulndb.Record, ecosystem, name string) []vulndb.Record {
	release := vulndb.EcosystemRelease(ecosystem)
	if release == "" {
		return records
	}
	base := vulndb.BaseEcosystem(ecosystem)
	out := make([]vulndb.Record, 0, len(records))
	for _, record := range records {
		for _, affected := range record.Affected {
			if vulndb.BaseEcosystem(affected.Ecosystem) == base && vulndb.EcosystemRelease(affected.Ecosystem) == release && dbAffectedName(affected) == vulndb.NormalizeName(base, name) {
				out = append(out, record)
				break
			}
		}
	}
	return out
}

func printDBMeta(meta vulndb.Meta) error {
	return printDBMetaTo(os.Stdout, meta)
}

func printDBMetaTo(w io.Writer, meta vulndb.Meta) error {
	ecosystems := make([]string, len(meta.Ecosystems))
	for i, ecosystem := range meta.Ecosystems {
		ecosystems[i] = httpx.Sanitize(ecosystem)
	}
	fmt.Fprintf(w, "Updated: %s\nRecords: %s\nEcosystems: %s\n", meta.UpdatedAt.UTC().Format(time.RFC3339), vulndb.FormatCount(meta.Records), strings.Join(ecosystems, ", "))
	for _, source := range meta.Sources {
		name := httpx.Sanitize(source.Name)
		feed := strings.Join(source.Ecosystems, ", ")
		if feed == "" {
			feed = source.URL
		}
		if feed != "" {
			name += " [" + httpx.Sanitize(feed) + "]"
		}
		fmt.Fprintf(w, "%s: %s records (%s); fetched %s; ETag=%s\n", name, vulndb.FormatCount(source.Records), vulndb.FormatBytes(source.Bytes), source.FetchedAt.UTC().Format(time.RFC3339), httpx.Sanitize(source.ETag))
		if source.Error != "" {
			warnf("db:error", "%s: %s\n", httpx.Sanitize(source.Name), httpx.Sanitize(source.Error))
		}
	}
	return nil
}

// dbHTTPClient allows command tests to serve feeds without external networking.
var dbHTTPClient = httpx.New

func cmdDBUpdate(ctx context.Context, fs *flag.FlagSet, db *string, args []string) error {
	sources := fs.String("source", "", "comma-separated sources: osv, alpine, debian, ghsa, nvd (opt-in)")
	nvdYears := fs.String("nvd-years", "", "NVD years: range or comma-separated list (default: current year and previous two)")
	ecosystems := fs.String("ecosystem", "", "comma-separated OSV ecosystems")
	releases := fs.String("alpine-release", "", "comma-separated Alpine releases (e.g. v3.20)")
	mirror := fs.String("mirror", "", "HTTPS OSV mirror base URL")
	force := fs.Bool("force", false, "fetch feeds without conditional request headers")
	noRaw := fs.Bool("no-keep-raw", false, "omit original feeds from installed database")
	maxBytes := fs.Int64("max-feed-bytes", vulndb.DefaultMaxFeedBytes, "maximum bytes per downloaded feed")
	maxUncompressed := fs.Int64("max-feed-uncompressed", vulndb.DefaultMaxFeedUncompressedBytes, "maximum total uncompressed bytes per OSV/GHSA archive")
	timeout := fs.Duration("timeout", 30*time.Minute, "overall update timeout")
	if err := parseCommandFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("db update takes no positional arguments")
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	if err := applyDBDefaults(fs, cfg.DB); err != nil {
		return err
	}
	if *maxBytes <= 0 || *timeout <= 0 {
		return errors.New("--max-feed-bytes and --timeout must be positive")
	}
	if *maxUncompressed <= 0 {
		return errors.New("--max-feed-uncompressed must be positive")
	}
	if offlineMode(cfg) {
		return errors.New("database update disabled: offline mode (BONGSU_OFFLINE or 'offline: true' in config)")
	}
	opts := vulndb.Options{
		Sources: splitCSV(*sources), Ecosystems: splitCSV(*ecosystems), AlpineReleases: splitCSV(*releases),
		OSVBaseURL: *mirror, Force: *force, NoKeepRaw: *noRaw, MaxFeedBytes: *maxBytes,
		MaxFeedUncompressedBytes: *maxUncompressed,
		Client:                   dbHTTPClient(*timeout),
		Progress:                 func(message string) { logf("db", "%s\n", httpx.Sanitize(message)) },
	}
	opts.Client.UserAgent = "bscan/" + version
	if err := setDBSigning(cfg, &opts); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	meta, err := vulndb.Update(ctx, filepath.Clean(*db), opts, vulndb.NVDOptions{Years: *nvdYears})
	if err != nil {
		if len(meta.Sources) > 0 {
			_ = printDBMetaTo(logWriter{stage: "db"}, meta)
		}
		return err
	}
	fmt.Println(filepath.Clean(*db))
	return printDBMetaTo(logWriter{stage: "db"}, meta)
}

func applyDBDefaults(fs *flag.FlagSet, cfg config.DBConfig) error {
	return applyFlagDefaults(fs, map[string]any{
		"source": strings.Join(cfg.Sources, ","), "ecosystem": strings.Join(cfg.Ecosystems, ","),
		"alpine-release": strings.Join(cfg.AlpineReleases, ","), "nvd-years": cfg.NVDYears,
		"max-feed-bytes": cfg.MaxFeedBytes, "max-feed-uncompressed": cfg.MaxFeedUncompressed,
		"no-keep-raw": !cfg.KeepRaw, "mirror": cfg.Mirror,
	})
}

func setDBSigning(cfg config.Config, opts *vulndb.Options) error {
	if strings.TrimSpace(cfg.Signer) != "" {
		path, err := config.Expand(cfg.PrivateKey)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			opts.PrivateKey, err = sign.ParsePrivate(data)
			if err != nil {
				return err
			}
			opts.Signer = cfg.Signer
		}
	}
	return nil
}

// Use the same PURL fallback as the catalog's package index.
func dbAffectedName(a vulndb.Affected) string {
	name := strings.TrimSpace(a.Package)
	if raw := strings.TrimSpace(a.PURL); raw != "" {
		if parsed, err := purl.Parse(raw); err == nil {
			eco := vulndb.PURLTypeToEcosystem(parsed.Type, parsed.Namespace)
			if eco != "" && vulndb.BaseEcosystem(eco) != vulndb.BaseEcosystem(a.Ecosystem) {
				return ""
			}
			if name == "" && eco != "" {
				name = parsed.FullName()
			}
		}
	}
	return vulndb.NormalizeName(a.Ecosystem, name)
}

// Retry only catalog lock contention. Other I/O, verification, and argument
// failures must remain immediate; the wait budget does not limit the operation.
func waitForCatalog(ctx context.Context, wait time.Duration, operation func() error) error {
	deadline := time.Now().Add(wait)
	announced := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := operation()
		busy := err != nil && strings.Contains(err.Error(), "database is locked or unavailable:") &&
			(errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, os.ErrExist))
		if !busy {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("catalog busy (another bscan process holds the lock); timed out after %s; retry the command: %w", wait, err)
		}
		if !announced {
			logf("db", "catalog busy (another bscan process holds the lock); retrying…\n")
			announced = true
		}
		timer := time.NewTimer(min(100*time.Millisecond, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
