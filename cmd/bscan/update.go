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
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/selfupdate"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

const (
	updateRepo          = "ziozzang/bongsu-scanner"
	updateCheckInterval = 24 * time.Hour
	updateCheckTimeout  = 5 * time.Second
	updateTimeout       = 10 * time.Minute
)

// updateCache is ~/.cache/bscan/update-check.json (or $BONGSU_HOME/cache/).
// A failed check is cached too (Latest empty, Error set) so air-gapped hosts
// attempt egress at most once per interval.
type updateCache struct {
	Checked time.Time `json:"checked_at"`
	Latest  string    `json:"latest,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// newHTTPClient returns the GitHub-restricted client with this build's UA.
func newHTTPClient(timeout time.Duration) *httpx.Client {
	c := selfupdate.NewClient(timeout)
	c.UserAgent = "bscan/" + version
	return c
}

// envTrue treats a set variable as true unless it is an explicit "off" value.
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// offlineMode reports whether all network access is disabled by environment
// (BONGSU_OFFLINE) or configuration (offline: true).
func offlineMode(cfg config.Config) bool {
	return envTrue("BONGSU_OFFLINE") || cfg.Offline
}

// releaseKey resolves the key used to verify SHA256SUMS.sig: the trusted key
// named "release" from the config first, then the built-in ReleasePublicKey.
// (nil, "", nil) means no key is available.
func releaseKey(cfg config.Config) (ed25519.PublicKey, string, error) {
	if _, ok := cfg.TrustedKeys["release"]; ok {
		pub, err := resolvePublic(cfg, "release")
		if err != nil {
			return nil, "", fmt.Errorf("trusted key 'release': %w", err)
		}
		return pub, "trusted:release", nil
	}
	if selfupdate.ReleasePublicKey != "" {
		pub, err := sign.ParsePublic([]byte(selfupdate.ReleasePublicKey))
		if err != nil {
			return nil, "", fmt.Errorf("built-in release key: %w", err)
		}
		return pub, "builtin", nil
	}
	return nil, "", nil
}

// releaseHTTPClient keeps explicit update requests testable without network access.
var releaseHTTPClient = newHTTPClient

func newReleaseUpdater(cfg config.Config, repo string, requireSignature bool) (*selfupdate.Updater, string, error) {
	key, source, err := releaseKey(cfg)
	if err != nil {
		return nil, "", err
	}
	return &selfupdate.Updater{
		Client:              releaseHTTPClient(updateTimeout),
		Repo:                repo,
		Token:               os.Getenv("GITHUB_TOKEN"), // explicit command only; never in background checks
		ReleaseKey:          key,
		RequireSignature:    requireSignature || cfg.UpdateRequireSignature || key != nil,
		SignatureMinVersion: cfg.SignatureMinVersion,
		Warn:                logWriter{stage: "update", warning: true},
	}, source, nil
}

func cmdUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "check without installing")
	force := fs.Bool("force", false, "install even if current")
	repo := fs.String("repo", updateRepo, "GitHub owner/repository")
	requireSig := fs.Bool("require-signature", false, "fail unless SHA256SUMS.sig verifies against a trusted 'release' key")
	if err := parseCommandFlags(fs, args); err != nil {
		return err
	}
	cfg, _, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	if offlineMode(cfg) {
		return errors.New("update disabled: offline mode (BONGSU_OFFLINE or 'offline: true' in config)")
	}
	u, keySource, err := newReleaseUpdater(cfg, *repo, *requireSig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	rel, err := u.Latest(ctx)
	if err != nil {
		return err
	}
	latest := httpx.Sanitize(rel.Version())
	if *check {
		fmt.Printf("current: %s\nlatest:  %s\n", httpx.Sanitize(version), latest)
	} else {
		logf("update", "current: %s; latest: %s", httpx.Sanitize(version), latest)
	}
	upToDate := !selfupdate.IsDevBuild(version) && selfupdate.Compare(latest, version) <= 0
	if *check || (upToDate && !*force) {
		if upToDate {
			logf("update", "bscan is up to date")
		}
		return nil
	}
	name, err := selfupdate.AssetName(latest)
	if err != nil {
		return err
	}
	asset, ok := rel.Find(name)
	if !ok {
		return fmt.Errorf("release %s has no asset %s", httpx.Sanitize(rel.TagName), name)
	}
	sums, err := u.Checksums(ctx, rel)
	if err != nil {
		return err
	}
	if sums.Entries[name] == "" {
		return fmt.Errorf("SHA256SUMS has no entry for %s", name)
	}
	printUpdateSignature(logWriter{stage: "update"}, keySource, sums)
	exe, err := selfupdate.Executable()
	if err != nil {
		return err
	}
	tmp, err := u.Download(ctx, asset, sums.Entries[name], filepath.Dir(exe))
	if err != nil {
		return err
	}
	dest, err := selfupdate.Replace(tmp, exe)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Printf("updated %s to %s\n", dest, latest)
	return nil
}

func printUpdateSignature(w io.Writer, keySource string, sums *selfupdate.Checksums) {
	if sums.Verified {
		signer := sums.Signer
		if !sums.Authenticated {
			signer += " (unauthenticated: v1 record)"
		}
		fmt.Fprintf(w, "[update] SHA256SUMS signature verified (key=%s signer=%s)\n", keySource, signer)
	}
}

// updateCheckSkipped reports whether the background update check must not run
// for this invocation: disabled by env/config, a command that must stay quiet
// or does its own networking, or a dev build.
func updateCheckSkipped(args []string) bool {
	if envTrue("BONGSU_NO_UPDATE_CHECK") || envTrue("BONGSU_OFFLINE") {
		return true
	}
	if len(args) == 0 || selfupdate.IsDevBuild(version) {
		return true
	}
	switch args[0] {
	case "update", "self-update", "db", "match", "version", "-v", "--version", "help", "-h", "--help", "about":
		return true
	}
	// If configuration cannot be read, its network policy is unknown.
	// Background checks must not bypass a possibly configured offline mode.
	if cfg, _, err := config.Load(); err != nil || cfg.Offline {
		return true
	}
	return false
}

// refreshUpdateCache is non-blocking and soft-fails for offline/air-gapped use.
func refreshUpdateCache(args []string) {
	if updateCheckSkipped(args) {
		return
	}
	if info, err := os.Stderr.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	path := updateCachePath()
	if path == "" {
		// No private cache location: never hit the network on every run.
		return
	}
	if c, ok := readUpdateCache(path); ok && !updateCacheStale(c, time.Now()) {
		if c.Latest != "" && selfupdate.Compare(c.Latest, version) > 0 {
			logf("update", "bscan %s is available; run 'bscan update'\n", c.Latest)
		}
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
		defer cancel()
		u := &selfupdate.Updater{Client: newHTTPClient(updateCheckTimeout), Repo: updateRepo, Warn: nil}
		entry := updateCache{Checked: time.Now()}
		if rel, err := u.Latest(ctx); err != nil {
			entry.Error = httpx.Sanitize(err.Error())
		} else {
			entry.Latest = rel.Version()
		}
		_ = writeUpdateCache(path, entry)
	}()
}

func updateCacheStale(c updateCache, now time.Time) bool {
	age := now.Sub(c.Checked)
	// A timestamp far in the future means a clock jump; treat it as stale.
	return c.Checked.IsZero() || age >= updateCheckInterval || age < -updateCheckInterval
}

// readUpdateCache loads and validates the cache. Any unparsable or suspicious
// value (a Latest that is not a version) is dropped so a bad cache can never
// break or spoof startup.
func readUpdateCache(path string) (updateCache, bool) {
	var c updateCache
	b, err := os.ReadFile(path)
	if err != nil {
		return c, false
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return updateCache{}, false
	}
	if c.Latest != "" && !selfupdate.IsVersion(c.Latest) {
		c.Latest = ""
	}
	if c.Checked.IsZero() {
		return updateCache{}, false
	}
	return c, true
}

func writeUpdateCache(path string, c updateCache) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".update-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// updateCachePath returns $BONGSU_HOME/cache/update-check.json when
// BONGSU_HOME is set, otherwise the XDG cache path. It returns "" when no
// per-user location exists (no HOME); there is no shared /tmp fallback.
func updateCachePath() string {
	if d := strings.TrimSpace(os.Getenv("BONGSU_HOME")); d != "" {
		return filepath.Join(d, "cache", "update-check.json")
	}
	d, err := os.UserCacheDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(d, "bscan", "update-check.json")
}
