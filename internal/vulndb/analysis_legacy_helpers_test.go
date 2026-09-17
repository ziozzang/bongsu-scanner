package vulndb

import (
	"compress/gzip"

	"context"

	"encoding/json"
	"errors"
	"fmt"

	"os"

	"path/filepath"

	"sort"

	_ "modernc.org/sqlite"
	"time"
)

// Legacy adapters retained for existing regression fixtures only.
func readRecords(path string, emit Emit) error {
	f, err := os.Open(path) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	return readRecordsReader(f, emit)
}

func writeRecords(path string, records []*Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { // #nosec G301 -- Catalog and feed directories contain distributable vulnerability data, not credentials.
		return err
	}
	f, err := os.Create(path) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	gz := gzip.NewWriter(f)
	var expanded int64
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = gz.Close()
			return err
		}
		if len(b)+1 >= 64<<20 || int64(len(b)+1) > (1<<30)-expanded {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = gz.Close()
			return errors.New("database record or expanded index exceeds size limit")
		}
		expanded += int64(len(b) + 1)
		if _, err = gz.Write(append(b, '\n')); err != nil {
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = gz.Close()
			return err
		}
	}
	if err = gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

func writeManifest(dir string, opts Options) error {
	return writeManifestContext(context.Background(), dir, opts)
}

// streamFeedCache applies the caller's expanded-byte budget and per-record
// bound while parsing. Nothing is retained in a per-feed record slice.
func streamFeedCache(ctx context.Context, feed Feed, rawPath, cachePath string, size int64, progress func(string), maxBytes int64, maxRecord int) (count int, err error) {
	return streamFeedCacheSpool(ctx, feed, rawPath, cachePath, size, progress, maxBytes, maxRecord, nil)
}

func buildLegacyIndexes(dir string, records map[string]*Record, meta *Meta) error {
	groups := map[string][]*Record{}
	ecos := map[string]bool{}
	paths := map[string]string{}
	for _, r := range records {
		seen := map[string]bool{}
		sortAffected(r.Affected)
		for _, a := range r.Affected {
			eco := BaseEcosystem(a.Ecosystem)
			if eco == "" {
				continue
			}
			if _, ok := affectedIndexName(a); !ok {
				continue
			}
			key := safeName(eco)
			if p, ok := paths[key]; ok && p != eco {
				return fmt.Errorf("ecosystem path collision: %q and %q", p, eco)
			}
			paths[key] = eco
			ecos[a.Ecosystem] = true
			if !seen[eco] {
				groups[eco] = append(groups[eco], r)
				seen[eco] = true
			}
		}
	}
	for eco, rs := range groups {
		firstName := func(r *Record) string {
			var names []string
			for _, a := range r.Affected {
				if BaseEcosystem(a.Ecosystem) == eco {
					if n, ok := affectedIndexName(a); ok {
						names = append(names, n)
					}
				}
			}
			if len(names) == 0 {
				return ""
			}
			sort.Strings(names)
			return names[0]
		}
		sort.Slice(rs, func(i, j int) bool {
			a, b := firstName(rs[i]), firstName(rs[j])
			if a == b {
				return rs[i].ID < rs[j].ID
			}
			return a < b
		})
		names := map[string][]int{}
		for i, r := range rs {
			seen := map[string]bool{}
			for _, a := range r.Affected {
				if BaseEcosystem(a.Ecosystem) != eco {
					continue
				}
				n, ok := affectedIndexName(a)
				if !ok {
					continue
				}
				if !seen[n] {
					names[n] = append(names[n], i)
					seen[n] = true
				}
			}
		}
		base := filepath.Join(dir, "index", safeName(eco))
		if err := writeRecords(filepath.Join(base, "records.jsonl.gz"), rs); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(base, "names.json"), names); err != nil {
			return err
		}
	}
	meta.Records = len(records)
	for e := range ecos {
		meta.Ecosystems = append(meta.Ecosystems, e)
	}
	sort.Strings(meta.Ecosystems)
	return nil
}

func installDatabase(stage, dir string) error {
	return installDatabaseContext(context.Background(), stage, dir)
}

// parseOSVZip walks a zip of OSV JSON files. accept filters member names
// (nil accepts every *.json). Corrupt or oversized members fail the feed so
// an update cannot install a silently incomplete replacement database.
func parseOSVZip(ctx context.Context, zipPath string, source string, accept func(name string) bool, emit Emit, progress func(string)) (int, error) {
	return parseOSVZipBounded(ctx, zipPath, source, accept, emit, progress, osvMaxEntries, osvMaxUncompressedBytes)
}

// buildIndexes is retained for package fixtures; production builds pass their
// cancellation context directly to buildSQLite.
func buildIndexes(dir string, records map[string]*Record, meta *Meta) error {
	return buildSQLite(context.Background(), dir, records, meta)
}

func openSQLiteSnapshot(dir string, m Meta, expectedDigest string) (Store, error) {
	return openSQLiteSnapshotContext(context.Background(), dir, m, expectedDigest)
}

func openSQLiteSnapshotContext(ctx context.Context, dir string, m Meta, expectedDigest string) (Store, error) {
	return openSQLiteSnapshotOptionsContext(ctx, dir, m, expectedDigest, Options{Isolation: "copy"}, nil)
}

func cloneOrCopySQLiteContext(ctx context.Context, src, dst string) error {
	_, err := isolateSQLiteContext(ctx, src, dst, true)
	return err
}

// setIngestionTimes preserves the first known local ingestion, including an
// unknown zero value for pre-timestamp catalogs. Only newly seen IDs acquire
// an AddedAt timestamp. The map is loaded once, not queried for every record.
func setIngestionTimes(ctx context.Context, dir string, old Meta, records map[string]*Record, now time.Time) error {
	previous, err := previousIngestionTimes(ctx, dir, old)
	if err != nil {
		return err
	}

	for id, r := range records {
		if added, exists := previous[id]; exists {
			r.AddedAt = added
		} else {
			r.AddedAt = now
		}
		r.LastSeenAt = now
	}
	return ctx.Err()
}

func (s *ingestionSpool) visit(ctx context.Context, previous map[string]time.Time, now time.Time, emit Emit) error {
	return visitIngestionSpools(ctx, []*ingestionSpool{s}, previous, now, emit)
}
