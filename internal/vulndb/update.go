package vulndb

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

// conversionCacheVersion must change whenever feed conversion semantics change.
// Stored per feed in SourceMeta so a 304 cannot reuse stale converted records.
const conversionCacheVersion = 6

// Update builds a complete replacement beside dir. Any failed feed leaves the
// current database intact; the returned metadata still describes every attempt.
func Update(ctx context.Context, dir string, opts Options, nvd ...NVDOptions) (Meta, error) {
	var meta Meta
	if len(nvd) > 1 {
		return meta, errors.New("at most one NVD configuration is supported")
	}
	if opts.Offline {
		return meta, errors.New("database update is unavailable in offline mode")
	}
	if err := ctx.Err(); err != nil {
		return meta, err
	}
	if opts.MaxFeedBytes <= 0 {
		opts.MaxFeedBytes = DefaultMaxFeedBytes
	}
	if opts.Client == nil {
		opts.Client = httpx.New(10 * time.Minute)
	}
	unlock, err := lockDatabase(dir)
	if err != nil {
		return meta, err
	}
	defer unlock()
	if err = recoverDatabaseContext(ctx, dir); err != nil {
		return meta, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+".tmp-")
	if err != nil {
		return meta, err
	}
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.RemoveAll(stage)
	}()
	var old Meta
	if _, err = os.Stat(dir); err == nil {
		if err := Verify(dir, nil); err != nil {
			return meta, err
		}
		if err := readJSON(filepath.Join(dir, "meta.json"), &old); err != nil {
			return meta, err
		}
		if old.SchemaVersion != SchemaVersion && old.SchemaVersion != 1 {
			return meta, fmt.Errorf("unsupported database schema %d", old.SchemaVersion)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return meta, err
	}
	previous := map[string]SourceMeta{}
	for _, m := range old.Sources {
		previous[m.Name+"\x00"+m.URL] = m
	}
	var nvdOpts NVDOptions
	if len(nvd) == 1 {
		nvdOpts = nvd[0]
	}
	selection := Selection{Sources: opts.Sources, Ecosystems: opts.Ecosystems, AlpineReleases: opts.AlpineReleases, NVDYears: nvdOpts.Years}
	if opts.ResolveSelection != nil {
		selection, err = opts.ResolveSelection(old)
		if err != nil {
			return meta, err
		}
	}
	selection.Ecosystems, err = NormalizeOSVEcosystems(selection.Ecosystems, opts.Progress)
	if err != nil {
		return meta, err
	}
	selection, err = selection.Normalize()
	if err != nil {
		return meta, err
	}
	opts.Sources, opts.Ecosystems, opts.AlpineReleases = selection.Sources, selection.Ecosystems, selection.AlpineReleases
	nvdOpts.Years = selection.NVDYears
	var feeds []Feed
	seen := map[string]bool{}
	for _, name := range selection.Sources {
		s, ok := LookupSource(name)
		if !ok {
			return meta, fmt.Errorf("unknown vulnerability source %q", name)
		}
		if seen[s.Name()] {
			continue
		}
		seen[s.Name()] = true
		if source, ok := s.(*nvdSource); ok {
			source.options = nvdOpts
		}
		fs, err := s.Feeds(&opts)
		if err != nil {
			return meta, err
		}
		feeds = append(feeds, fs...)
	}
	if len(feeds) == 0 {
		return meta, errors.New("no vulnerability feeds selected")
	}
	meta = Meta{SchemaVersion: SchemaVersion, UpdatedAt: time.Now().UTC(), Selection: &selection}
	spools := make([]*ingestionSpool, len(feeds))
	feedPaths := map[string]bool{}
	for _, feed := range feeds {
		if err := ctx.Err(); err != nil {
			return meta, err
		}
		if !safeRelative(feed.Source) || strings.Contains(feed.Source, "/") || !safeRelative(feed.File) || strings.Contains(feed.File, "/") || !safeRelative(feed.Key) || strings.Contains(feed.Key, "/") {
			return meta, errors.New("unsafe source feed path")
		}
		cacheRel := filepath.Join("cache", feed.Source, feed.Key+".jsonl.gz")
		rawRel := filepath.Join("raw", feed.Source, feed.File)
		if feedPaths[cacheRel] || feedPaths[rawRel] {
			return meta, fmt.Errorf("duplicate source feed path %q", feed.Key)
		}
		feedPaths[cacheRel] = true
		feedPaths[rawRel] = true
	}
	var progressMu sync.Mutex
	if progress := opts.Progress; progress != nil {
		opts.Progress = func(message string) { progressMu.Lock(); defer progressMu.Unlock(); progress(message) }
	}
	results := make([]SourceMeta, len(feeds))
	feedErrors := make([]error, len(feeds))
	started := make([]bool, len(feeds))
	jobs := make(chan int, len(feeds))
	for i := range feeds {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for n := 0; n < min(3, len(feeds)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					feedErrors[i] = err
					continue
				}
				started[i] = true
				spool, err := newIngestionSpool(stage)
				if err != nil {
					feedErrors[i] = err
					continue
				}
				spools[i] = spool
				results[i], feedErrors[i] = updateFeed(ctx, dir, stage, feeds[i], previous, opts, meta.UpdatedAt, spool)
				feedErrors[i] = errors.Join(feedErrors[i], spool.close())
			}
		}()
	}
	workers.Wait()
	var failures []error
	var notStarted, interrupted int
	for i, feed := range feeds {
		if ctx.Err() != nil && errors.Is(feedErrors[i], ctx.Err()) {
			if started[i] {
				interrupted++
			} else {
				notStarted++
			}
			continue
		}
		m := results[i]
		if m.Name == "" {
			m = SourceMeta{Name: feed.Source, URL: feed.URL, Ecosystems: feed.Ecosystems, FetchedAt: meta.UpdatedAt}
		}
		if err := feedErrors[i]; err != nil {
			m.Error = httpx.Sanitize(err.Error())
			failures = append(failures, fmt.Errorf("%q %q: %w", feed.Source, feed.Key, terminalSafeError{err}))
		}
		meta.Sources = append(meta.Sources, m)
	}

	if err := ctx.Err(); err != nil {
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("update interrupted: %d feeds not started; %d feeds interrupted", notStarted, interrupted))
		}
		return meta, errors.Join(append(failures, err)...)
	}
	if len(failures) > 0 {
		return meta, errors.Join(failures...)
	}
	if err := ctx.Err(); err != nil {
		return meta, err
	}
	previousTimes, err := previousIngestionTimes(ctx, dir, old)
	if err != nil {
		return meta, err
	}
	if err = buildSQLiteStream(ctx, stage, func(emit Emit) error { return visitIngestionSpools(ctx, spools, previousTimes, meta.UpdatedAt, emit) }, &meta); err != nil {
		return meta, err
	}
	for _, spool := range spools {
		if err = os.RemoveAll(spool.dir); err != nil {
			return meta, err
		}
	}

	if err = writeJSON(filepath.Join(stage, "meta.json"), meta); err != nil {
		return meta, err
	}
	if err = writeManifestContext(ctx, stage, opts); err != nil {
		return meta, err
	}
	if err = VerifyContext(ctx, stage, nil); err != nil {
		return meta, err
	}
	if err = ctx.Err(); err != nil {
		return meta, err
	}
	if err = installDatabaseContext(ctx, stage, dir); err != nil {
		return meta, err
	}
	return meta, nil
}

// updateFeed owns its cache and spool. The caller merges completed feeds in
// selection order, independently of download/parse completion order.
func updateFeed(ctx context.Context, dir, stage string, feed Feed, previous map[string]SourceMeta, opts Options, now time.Time, spool *ingestionSpool) (SourceMeta, error) {
	if err := ctx.Err(); err != nil {
		return SourceMeta{Name: feed.Source, URL: feed.URL}, err
	}
	cacheRel := filepath.Join("cache", feed.Source, feed.Key+".jsonl.gz")
	rawRel := filepath.Join("raw", feed.Source, feed.File)
	var prev *SourceMeta
	if m, ok := previous[feed.Source+"\x00"+feed.URL]; ok {
		if _, err := os.Stat(filepath.Join(dir, cacheRel)); err == nil {
			prev = &m
		}
	}
	if feed.MaxBytes <= 0 {
		feed.MaxBytes = opts.MaxFeedBytes
	}
	staleConversion := prev != nil && prev.ConversionVersion != conversionCacheVersion
	// Converted JSON size cannot stand in for the original archive's expansion:
	// descriptions and ignored members can disappear during conversion.
	expansionLimited := feed.Source == SourceOSV || feed.Source == SourceGHSA || feed.Source == SourceRedHatVEX
	cacheMetaRel := cacheRel + ".meta.json"
	if prev != nil && expansionLimited {
		var cached feedExpansionMeta
		if err := readJSON(filepath.Join(dir, cacheMetaRel), &cached); err != nil ||
			cached.Version != 1 || cached.SHA256 != prev.SHA256 ||
			cached.ExpandedBytes > opts.maxFeedUncompressedBytes() {
			staleConversion = true
		}
	}
	force := opts.Force
	if staleConversion {
		if _, err := os.Stat(filepath.Join(dir, rawRel)); errors.Is(err, os.ErrNotExist) {
			force = true
		} else if err != nil {
			return SourceMeta{Name: feed.Source, URL: feed.URL}, err
		}
	}
	fetched, err := fetchFeed(ctx, opts.Client, feed, prev, filepath.Join(stage, rawRel), force, now)
	if err == nil && fetched.NotModified && staleConversion {
		err = copyFileContext(ctx, filepath.Join(dir, rawRel), filepath.Join(stage, rawRel))
		fetched.NotModified = false // Reparse retained bytes with current conversion and limits.
	}
	var parsedCount int
	var dataThrough time.Time
	trackModified := func(r *Record) {
		if modified, err := time.Parse(time.RFC3339Nano, r.Modified); err == nil && modified.After(dataThrough) {
			dataThrough = modified.UTC()
		}
	}
	cacheLimit := feedCacheLimit(feed.Source, opts)
	if err == nil && fetched.NotModified {
		err = readFeedCache(filepath.Join(dir, cacheRel), cacheLimit, func(r *Record) error {
			if !validID(r.ID) {
				return errors.New("feed emitted invalid advisory")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			addProvenance(r, RecordSource{Name: feed.Source, URL: feed.URL})
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if err := spool.append(r.ID, append(b, '\n')); err != nil {
				return err
			}
			trackModified(r)
			parsedCount++
			return nil
		})
		if err == nil {
			err = copyFileContext(ctx, filepath.Join(dir, cacheRel), filepath.Join(stage, cacheRel))
		}
		if err == nil && expansionLimited {
			err = copyFileContext(ctx, filepath.Join(dir, cacheMetaRel), filepath.Join(stage, cacheMetaRel))
		}
		if err == nil && !opts.NoKeepRaw {
			if _, statErr := os.Stat(filepath.Join(dir, rawRel)); statErr == nil {
				err = copyFileContext(ctx, filepath.Join(dir, rawRel), filepath.Join(stage, rawRel))
			}
		}
	} else if err == nil {
		var progress func(string)
		if opts.Progress != nil {
			progress = func(s string) { opts.Progress(httpx.Sanitize(s)) }
		}
		var vexExpanded uint64
		parse := feed.Parse
		if feed.Source == SourceRedHatVEX {
			parse = func(ctx context.Context, path string, _ int64, emit Emit, progress func(string)) error {
				var err error
				vexExpanded, err = parseRedHatVEXExpanded(ctx, path, opts.maxFeedUncompressedBytes(), vexMaxDocument, emit, progress)
				return err
			}
		}
		feed.Parse = func(ctx context.Context, path string, size int64, emit Emit, progress func(string)) error {
			return parse(ctx, path, size, func(r *Record) error { trackModified(r); return emit(r) }, progress)
		}
		parsedCount, err = streamFeedCacheSpool(ctx, feed, filepath.Join(stage, rawRel), filepath.Join(stage, cacheRel), fetched.Meta.Bytes, progress, cacheLimit, 64<<20, spool.append)
		if err == nil && expansionLimited {
			var expanded uint64
			if feed.Source == SourceRedHatVEX {
				expanded = vexExpanded
			} else {
				expanded, err = feedExpandedBytes(ctx, filepath.Join(stage, rawRel))
			}
			if err == nil {
				err = writeJSON(filepath.Join(stage, cacheMetaRel), feedExpansionMeta{Version: 1, SHA256: fetched.Meta.SHA256, ExpandedBytes: expanded})
			}
		}
	}
	m := fetched.Meta
	m.Records = parsedCount
	if err == nil {
		m.ConversionVersion = conversionCacheVersion
		m.DataThrough = dataThrough
	}
	if err != nil {
		m.Error = httpx.Sanitize(err.Error())

	}
	if opts.Progress != nil && !(ctx.Err() != nil && errors.Is(err, ctx.Err())) {
		opts.Progress(fmt.Sprintf("[db:%s] %s: %s records (%s)%s", httpx.Sanitize(feed.Source), httpx.Sanitize(feed.Key), formatCount(m.Records), formatBytes(m.Bytes), func() string {
			if m.Error != "" {
				return ": " + m.Error
			}
			return ""
		}()))
	}
	if opts.NoKeepRaw {
		_ = os.Remove(filepath.Join(stage, rawRel))
	}
	return m, err
}

// Stored beside each converted OSV/GHSA/VEX cache and included in the database
// manifest. Missing/obsolete metadata requires parsing the original feed again.
type feedExpansionMeta struct {
	Version       int    `json:"version"`
	SHA256        string `json:"sha256"`
	ExpandedBytes uint64 `json:"expanded_bytes"`
}

func feedExpandedBytes(ctx context.Context, filename string) (uint64, error) {
	zr, err := zip.OpenReader(filename)
	if err != nil {
		return 0, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = zr.Close()
	}()
	var expanded uint64
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if f.UncompressedSize64 > math.MaxUint64-expanded {
			return 0, errors.New("feed expanded size overflows uint64")
		}
		expanded += f.UncompressedSize64
	}
	return expanded, nil
}

// Converted OSV/GHSA feeds can exceed the legacy 1 GiB cache budget too.
// Use the configured expansion budget for both cache writes and 304 reads,
// retaining the legacy minimum because conversion adds provenance metadata.
func feedCacheLimit(source string, opts Options) int64 {
	limit := int64(1 << 30)
	if source == SourceOSV || source == SourceGHSA || source == SourceRedHatVEX {
		limit = max(limit, int64(opts.maxFeedUncompressedBytes())) // #nosec G115 -- maxFeedUncompressedBytes returns a positive int64 option or the 32 GiB default.
	}
	// readRecordsBounded reserves one extra byte to detect an exceeded limit.
	return min(limit, math.MaxInt64-1)
}

func readFeedCache(path string, maxBytes int64, emit Emit) error {
	f, err := os.Open(path) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	return readRecordsBounded(f, emit, maxBytes, 64<<20)
}

func streamFeedCacheSpool(ctx context.Context, feed Feed, rawPath, cachePath string, size int64, progress func(string), maxBytes int64, maxRecord int, spool func(string, []byte) error) (count int, err error) {
	if err = os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
		return
	}
	f, err := os.Create(cachePath) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return 0, err
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	defer func() {
		err = errors.Join(err, gz.Close(), f.Close(), ctx.Err())
		if err != nil {
			_ = os.Remove(cachePath)
		}
	}()
	var expanded int64
	err = feed.Parse(ctx, rawPath, size, func(r *Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r == nil || !validID(r.ID) {
			return errors.New("feed emitted invalid advisory")
		}
		addProvenance(r, RecordSource{Name: feed.Source, URL: feed.URL})
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(b)+1 >= maxRecord || int64(len(b)+1) > maxBytes-expanded {
			return errors.New("database record or expanded index exceeds size limit")
		}
		expanded += int64(len(b) + 1)
		b = append(b, '\n')
		if _, err = gz.Write(b); err != nil {
			return err
		}
		if spool != nil {
			if err = spool(r.ID, b); err != nil {
				return err
			}
		}
		count++
		return nil
	}, progress)
	return
}

func copyFileContext(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = in.Close()
	}()
	out, err := os.Create(dst) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, contextReader{ctx: ctx, r: in})
	closeErr := out.Close()
	if err = errors.Join(copyErr, closeErr, ctx.Err()); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}
func lockDatabase(dir string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
		return nil, err
	}
	return acquireDatabaseLock(dir + ".lock")
}

func recoverDatabaseContext(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prev := dir + ".prev"
	if _, err := os.Lstat(prev); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := VerifyContext(ctx, prev, nil); err != nil {
		return fmt.Errorf("cannot recover interrupted database install: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(prev, dir); err != nil {
		return fmt.Errorf("restore previous database: %w", err)
	}
	return nil
}

func installDatabaseContext(ctx context.Context, stage, dir string) error {
	if err := recoverDatabaseContext(ctx, dir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prev := dir + ".prev"
	if err := os.RemoveAll(prev); err != nil {
		return err
	}
	hadOld := false
	if _, err := os.Stat(dir); err == nil {
		if err = os.Rename(dir, prev); err != nil {
			return err
		}
		hadOld = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ctx.Err(); err != nil {
		if hadOld {
			if rollback := os.Rename(prev, dir); rollback != nil {
				return errors.Join(err, rollback)
			}
		}
		return err
	}
	if err := os.Rename(stage, dir); err != nil {
		if hadOld {
			if rollback := os.Rename(prev, dir); rollback != nil {
				return errors.Join(err, rollback)
			}
		}
		return err
	}
	return nil
}
