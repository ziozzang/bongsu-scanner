package vulndb

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

const vexListMaxBytes = 16 << 20

var vexDeltaPath = regexp.MustCompile(`^[0-9]{4}/cve-[0-9]{4}-[0-9]{4,}\.json$`)
var errVEXBudget = errors.New("redhat-vex: delta byte budget exhausted")

type vexDeltaEntry struct {
	Path    string
	At      time.Time
	Deleted bool
}

func (e vexDeltaEntry) key() string { return fmt.Sprintf("%t:%s", e.Deleted, e.Path) }
func (e vexDeltaEntry) id() string  { return strings.ToUpper(strings.TrimSuffix(e.Path[5:], ".json")) }

type vexDeltaFeed struct {
	baseURL      string
	archiveDate  time.Time
	client       *httpx.Client
	budget       int64
	maxDocuments int
	maxDocument  int64
	retryDelay   time.Duration
	// Populated by updateVEXDeltaFeed before Parse, never shared between workers.
	cacheLimit int64
	oldCache   string
	ledger     map[string]time.Time
	meta       SourceMeta
}

// Small lists are retained in cache even with --no-keep-raw: a 304 must still
// permit retrying unfinished documents, and deletions can change independently.
func updateVEXDeltaFeed(ctx context.Context, dir, stage string, feed Feed, previous map[string]SourceMeta, opts Options, now time.Time, spool *ingestionSpool) (SourceMeta, error) {
	d := feed.vexDelta
	cacheRel := filepath.Join("cache", feed.Source, feed.Key+".jsonl.gz")
	listRel := filepath.Join("cache", feed.Source, "changes.csv")
	ledgerRel := cacheRel + ".ledger.json"
	old, exists := previous[feed.Source+"\x00"+feed.URL]
	reusable := exists && old.ArchiveDate.Equal(d.archiveDate) && old.ConversionVersion == conversionCacheVersion && !opts.Force
	d.ledger = map[string]time.Time{}
	d.oldCache = ""
	d.cacheLimit = feedCacheLimit(feed.Source, opts)
	d.meta = SourceMeta{ArchiveDate: d.archiveDate}
	if reusable {
		if err := readJSON(filepath.Join(dir, ledgerRel), &d.ledger); err != nil {
			return d.meta, err
		}
		d.oldCache = filepath.Join(dir, cacheRel)
		d.meta.DeltaThrough, d.meta.DeltaDocuments, d.meta.DeltaDeleted = old.DeltaThrough, old.DeltaDocuments, old.DeltaDeleted
	}
	var prev *SourceMeta
	if exists {
		prev = &old
	}
	fetched, err := fetchFeed(ctx, d.client, feed, prev, filepath.Join(stage, listRel), opts.Force, now)
	if err != nil {
		return fetched.Meta, err
	}
	if fetched.NotModified {
		if opts.Progress != nil {
			opts.Progress("redhat-vex changes.csv: not modified (304)")
		}
		if err := copyFileContext(ctx, filepath.Join(dir, listRel), filepath.Join(stage, listRel)); err != nil {
			return fetched.Meta, err
		}
	}
	// Parse always runs, including a changes.csv 304, to apply independent
	// deletions and resume a bounded update from its per-event ledger.
	var progress func(string)
	if opts.Progress != nil {
		progress = func(s string) { opts.Progress(httpx.Sanitize(s)) }
	}
	count, err := streamFeedCacheSpool(ctx, feed, filepath.Join(stage, listRel), filepath.Join(stage, cacheRel), fetched.Meta.Bytes, progress, feedCacheLimit(feed.Source, opts), 64<<20, spool.append)
	m := fetched.Meta
	m.ArchiveDate = d.archiveDate
	m.DeltaThrough, m.DeltaDocuments, m.DeltaDeleted = d.meta.DeltaThrough, d.meta.DeltaDocuments, d.meta.DeltaDeleted
	m.DeltaFetched, m.DeltaMalformed, m.DeltaOversized, m.DeltaRemaining, m.DeltaBytes = d.meta.DeltaFetched, d.meta.DeltaMalformed, d.meta.DeltaOversized, d.meta.DeltaRemaining, d.meta.DeltaBytes
	m.DataThrough, m.Records = d.meta.DataThrough, count
	if err == nil {
		err = writeJSON(filepath.Join(stage, ledgerRel), d.ledger)
	}
	if err == nil {
		m.ConversionVersion = conversionCacheVersion
	} else {
		m.Error = httpx.Sanitize(err.Error())
	}
	if progress != nil {
		progress(fmt.Sprintf("redhat-vex deltas: fetched=%d documents=%d deleted=%d malformed=%d oversized=%d remaining=%d bytes=%d", m.DeltaFetched, m.DeltaDocuments, m.DeltaDeleted, m.DeltaMalformed, m.DeltaOversized, m.DeltaRemaining, m.DeltaBytes))
	}
	return m, err
}

func readVEXDeltaList(ctx context.Context, filename string, deleted bool, archive time.Time, ledger map[string]time.Time) ([]vexDeltaEntry, int, error) {
	f, err := os.Open(filename) // #nosec G304 -- Caller supplies a downloaded file within the stage directory.
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	scan := bufio.NewScanner(io.LimitReader(f, vexListMaxBytes+1))
	scan.Buffer(make([]byte, 4096), vexListMaxBytes+2)
	entries := map[string]vexDeltaEntry{}
	malformed, size := 0, 0
	for scan.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, malformed, err
		}
		size += len(scan.Bytes()) + 1
		if size > vexListMaxBytes {
			return nil, malformed, httpx.ErrTooLarge
		}
		if len(scan.Bytes()) > 512 {
			malformed++
			continue
		}
		row, err := csv.NewReader(strings.NewReader(scan.Text())).Read()
		if err != nil || len(row) != 2 || !vexDeltaPath.MatchString(row[0]) || !validID(strings.ToUpper(strings.TrimSuffix(row[0][5:], ".json"))) {
			malformed++
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, row[1])
		if err != nil {
			malformed++
			continue
		}
		e := vexDeltaEntry{Path: row[0], At: at.UTC(), Deleted: deleted}
		if !e.At.After(archive) || !e.At.After(ledger[e.key()]) {
			continue
		}
		if prev, ok := entries[e.Path]; !ok || e.At.After(prev.At) {
			entries[e.Path] = e
		}
	}
	if err := scan.Err(); err != nil {
		return nil, malformed, err
	}
	out := make([]vexDeltaEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	return out, malformed, nil
}

func (d *vexDeltaFeed) parse(ctx context.Context, path string, _ int64, emit Emit, progress func(string)) error {
	// Both the temporary converted partitions and the four document spools are
	// under the feed's stage directory, and removed before catalog installation.
	if d.ledger == nil {
		d.ledger = map[string]time.Time{}
	}
	stage := filepath.Dir(path)
	pending, bad, err := readVEXDeltaList(ctx, path, false, d.archiveDate, d.ledger)
	d.meta.DeltaMalformed += bad
	if err != nil {
		return err
	}
	deletionPath := filepath.Join(stage, "deletions.csv")
	deletionFeed := Feed{Source: SourceRedHatVEX, URL: d.baseURL + "deletions.csv", MaxBytes: vexListMaxBytes}
	if _, err := fetchFeed(ctx, d.client, deletionFeed, nil, deletionPath, false, time.Now()); err != nil {
		return err
	}
	defer func() { _ = os.Remove(deletionPath) }()
	deleted, bad, err := readVEXDeltaList(ctx, deletionPath, true, d.archiveDate, d.ledger)
	d.meta.DeltaMalformed += bad
	if err != nil {
		return err
	}
	pending = append(pending, deleted...)
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].At.Equal(pending[j].At) {
			return pending[i].At.Before(pending[j].At)
		}
		return pending[i].key() < pending[j].key()
	})
	// A deletion supersedes a change for the same path, avoiding pointless 404s.
	latest := map[string]vexDeltaEntry{}
	for _, e := range pending {
		latest[e.Path] = e
	}
	selected := pending[:0]
	for _, e := range pending {
		if latest[e.Path] == e {
			selected = append(selected, e)
		}
	}
	pending = selected
	sp, err := newIngestionSpool(stage)
	if err != nil {
		return err
	}
	defer func() { _ = sp.close(); _ = os.RemoveAll(sp.dir) }()
	appendRecord := func(r *Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return sp.append(r.ID, append(b, '\n'))
	}
	if d.oldCache != "" {
		if err := readFeedCache(d.oldCache, d.cacheLimit, appendRecord); err != nil {
			return err
		}
	}
	budget := &vexDeltaBudget{left: d.budget}
	processed := 0
	for processed < len(pending) && processed < d.maxDocuments {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(processed+4, len(pending), d.maxDocuments)
		batch := pending[processed:end]
		results := make([]vexDeltaResult, len(batch))
		var wg sync.WaitGroup
		for i, e := range batch {
			wg.Add(1)
			go func() { defer wg.Done(); results[i] = d.document(ctx, stage, e, budget) }()
		}
		wg.Wait()
		stop := false
		for i, result := range results {
			e := batch[i]
			if errors.Is(result.err, errVEXBudget) {
				stop = true
				continue
			}
			if result.err != nil {
				return result.err
			}
			if result.oversized {
				d.meta.DeltaOversized++
			} else if result.malformed {
				d.meta.DeltaMalformed++
			} else {
				if err := appendRecord(result.record); err != nil {
					return err
				}
				if e.Deleted {
					d.meta.DeltaDeleted++
				} else {
					d.meta.DeltaDocuments++
					d.meta.DeltaFetched++
				}
				if e.At.After(d.meta.DeltaThrough) {
					d.meta.DeltaThrough = e.At
				}
			}
			// Individual checkpoints preserve ties, late entries and budget gaps.
			// Rejected documents are retried only when the publisher changes their row.
			d.ledger[e.key()] = e.At
		}
		processed = end
		if progress != nil && processed%100 == 0 {
			progress(fmt.Sprintf("redhat-vex deltas: processed=%d/%d", processed, len(pending)))
		}
		if stop {
			break
		}
	}
	for _, e := range pending {
		if e.At.After(d.ledger[e.key()]) {
			d.meta.DeltaRemaining++
		}
	}
	d.meta.DeltaBytes = d.budget - budget.left
	if err := sp.close(); err != nil {
		return err
	}
	return visitMergedIngestionSpools(ctx, []*ingestionSpool{sp}, nil, time.Time{}, func(r *Record) error {
		if at, err := time.Parse(time.RFC3339Nano, r.Modified); err == nil && at.After(d.meta.DataThrough) {
			d.meta.DataThrough = at.UTC()
		}
		return emit(r)
	})
}

type vexDeltaResult struct {
	record               *Record
	malformed, oversized bool
	err                  error
}
type vexDeltaBudget struct {
	mu   sync.Mutex
	left int64
}
type vexDeltaWriter struct {
	budget *vexDeltaBudget
	out    io.Writer
}

func (w vexDeltaWriter) Write(p []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	if int64(len(p)) > w.budget.left {
		return 0, errVEXBudget
	}
	n, err := w.out.Write(p)
	w.budget.left -= int64(n)
	return n, err
}

func (d *vexDeltaFeed) document(ctx context.Context, stage string, e vexDeltaEntry, budget *vexDeltaBudget) vexDeltaResult {
	if e.Deleted {
		return vexDeltaResult{record: &Record{ID: e.id(), Source: SourceRedHatVEX, Modified: e.At.Format(time.RFC3339Nano), Withdrawn: e.At.Format(time.RFC3339Nano)}}
	}
	f, err := os.CreateTemp(stage, ".vex-delta-*.json")
	if err != nil {
		return vexDeltaResult{err: err}
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	for attempt := 0; ; attempt++ {
		if err = f.Truncate(0); err != nil {
			return vexDeltaResult{err: err}
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return vexDeltaResult{err: err}
		}
		_, _, _, err = d.client.Download(ctx, d.baseURL+e.Path, nil, vexDeltaWriter{budget, f}, d.maxDocument)
		if err == nil || attempt == 2 || !vexRetryable(err) {
			break
		}
		timer := time.NewTimer(d.retryDelay << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return vexDeltaResult{err: ctx.Err()}
		case <-timer.C:
		}
	}
	if errors.Is(err, httpx.ErrTooLarge) {
		return vexDeltaResult{oversized: true}
	}
	if err != nil {
		return vexDeltaResult{err: err}
	}
	doc, err := decodeRedHatVEX(ctx, f)
	if ctx.Err() != nil {
		return vexDeltaResult{err: ctx.Err()}
	}
	if err != nil {
		return vexDeltaResult{malformed: true}
	}
	r, err := convertRedHatVEX(ctx, doc)
	if ctx.Err() != nil {
		return vexDeltaResult{err: ctx.Err()}
	}
	if err != nil || doc.Document.Tracking.ID != e.id() {
		return vexDeltaResult{malformed: true}
	}
	at, err := time.Parse(time.RFC3339Nano, doc.Document.Tracking.Modified)
	if err != nil {
		return vexDeltaResult{malformed: true}
	}
	// A valid document that no longer mentions RHEL must clear the archive's
	// RHEL entries too, rather than disappear during filtering.
	if r == nil {
		r = &Record{ID: e.id(), Source: SourceRedHatVEX, Modified: at.UTC().Format(time.RFC3339Nano)}
	}
	return vexDeltaResult{record: r}
}
func vexRetryable(err error) bool {
	var status *httpx.StatusError
	if errors.As(err, &status) {
		return status.StatusCode == http.StatusTooManyRequests || status.StatusCode >= 500
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.ErrUnexpectedEOF)
}

// VEXStatus returns the source-specific freshness line; callers need no new
// SQLite columns because SourceMeta is already persisted in signed meta.json.
func (m SourceMeta) VEXStatus() string {
	if m.Name != SourceRedHatVEX || m.ArchiveDate.IsZero() {
		return ""
	}
	through := "none"
	if !m.DeltaThrough.IsZero() {
		through = m.DeltaThrough.UTC().Format("2006-01-02T15:04Z")
	}
	return fmt.Sprintf("archive %s, deltas through %s (%s documents); deleted=%d skipped=%d remaining=%d", m.ArchiveDate.UTC().Format(time.DateOnly), through, formatCount(m.DeltaDocuments), m.DeltaDeleted, m.DeltaMalformed+m.DeltaOversized, m.DeltaRemaining)
}

// Resolve VEX versions before a same-ID record from another source can turn
// their provenance into a comma-joined source. Keep the original source order
// for all cross-source union rules (including summary/severity preference).
func consolidateVEXSpools(ctx context.Context, stage string, feeds []Feed, spools []*ingestionSpool) ([]*ingestionSpool, error) {
	var vex []*ingestionSpool
	for i, feed := range feeds {
		if feed.Source == SourceRedHatVEX {
			vex = append(vex, spools[i])
		}
	}
	if len(vex) < 2 || len(vex) == len(spools) {
		return spools, nil
	}
	merged, err := newIngestionSpool(stage)
	if err != nil {
		return nil, err
	}
	err = visitMergedIngestionSpools(ctx, vex, nil, time.Time{}, func(r *Record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return merged.append(r.ID, append(b, '\n'))
	})
	if err = errors.Join(err, merged.close()); err != nil {
		return nil, err
	}
	out := make([]*ingestionSpool, 0, len(spools)-len(vex)+1)
	inserted := false
	for i, feed := range feeds {
		if feed.Source != SourceRedHatVEX {
			out = append(out, spools[i])
			continue
		}
		if !inserted {
			out = append(out, merged)
			inserted = true
		}
		if err := os.RemoveAll(spools[i].dir); err != nil {
			return nil, err
		}
	}
	return out, nil
}
