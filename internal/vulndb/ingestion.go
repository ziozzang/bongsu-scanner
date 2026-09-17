package vulndb

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func previousIngestionTimes(ctx context.Context, dir string, old Meta) (_ map[string]time.Time, resultErr error) {
	previous := map[string]time.Time{}
	if old.SchemaVersion != 0 {
		st, err := openVerifiedSnapshotContext(ctx, dir, nil)
		if errors.Is(err, ErrUnsupportedCatalog) {
			// The installed catalog predates this binary's format; it is
			// being rebuilt, so first-seen times cannot be carried over.
			st, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
		if st == nil {
			// no usable previous catalog
		} else if sqlite, ok := st.(*sqliteStore); ok {
			defer func() { resultErr = errors.Join(resultErr, st.Close()) }()
			rows, err := sqlite.conn.QueryContext(ctx, "SELECT id,added_at FROM records")
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var id string
				var added sql.NullString
				if err = rows.Scan(&id, &added); err != nil {
					// Cleanup only; read errors or the primary operation error are handled separately.
					_ = rows.Close()
					return nil, err
				}
				var at time.Time
				if added.Valid && added.String != "" {
					at, err = time.Parse(time.RFC3339Nano, added.String)
					if err != nil {
						// Cleanup only; read errors or the primary operation error are handled separately.
						_ = rows.Close()
						return nil, err
					}
				}
				previous[id] = at
			}
			err = rows.Err()
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = rows.Close()
			if err != nil {
				return nil, err
			}
		} else {
			defer func() { resultErr = errors.Join(resultErr, st.Close()) }()
			if err := visitStoreRecords(ctx, st, func(r *Record) error { previous[r.ID] = r.AddedAt; return nil }); err != nil {
				return nil, err
			}
		}
	}
	return previous, ctx.Err()
}

// Feed records spill into deterministic ID partitions while the compressed
// caches are written. Only one partition is decoded/merged at a time, avoiding
// a catalog-sized pointer graph and a second decode of every fresh feed cache.
const ingestionPartitions = 64

type ingestionSpool struct {
	dir     string
	files   [ingestionPartitions]*os.File
	writers [ingestionPartitions]*bufio.Writer
}

func newIngestionSpool(stage string) (*ingestionSpool, error) {
	dir, err := os.MkdirTemp(stage, ".merge-")
	if err != nil {
		return nil, err
	}
	return &ingestionSpool{dir: dir}, nil
}
func (s *ingestionSpool) append(id string, data []byte) error {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	i := h.Sum64() % ingestionPartitions
	if s.files[i] == nil {
		f, err := os.Create(filepath.Join(s.dir, fmt.Sprint(i)))
		if err != nil {
			return err
		}
		s.files[i] = f
		s.writers[i] = bufio.NewWriterSize(f, 64<<10)
	}
	_, err := s.writers[i].Write(data)
	return err
}
func (s *ingestionSpool) close() error {
	var failures []error
	for i, f := range s.files {
		if f != nil {
			failures = append(failures, s.writers[i].Flush(), f.Close())
			s.files[i], s.writers[i] = nil, nil
		}
	}
	return errors.Join(failures...)
}

func visitIngestionSpools(ctx context.Context, spools []*ingestionSpool, previous map[string]time.Time, now time.Time, emit Emit) error {
	// Build from fully merged records across all ID partitions before enriching
	// anything. Keep only CVSS candidates in memory, not the entire catalog.
	index := aliasSeverityIndex{}
	if err := visitMergedIngestionSpools(ctx, spools, previous, now, func(r *Record) error {
		index.add(r)
		return nil
	}); err != nil {
		return err
	}
	return visitMergedIngestionSpools(ctx, spools, previous, now, func(r *Record) error {
		index.apply(r)
		return emit(r)
	})
}

func visitMergedIngestionSpools(ctx context.Context, spools []*ingestionSpool, previous map[string]time.Time, now time.Time, emit Emit) error {
	for i := 0; i < ingestionPartitions; i++ {
		if err := visitIngestionPartition(ctx, spools, i, previous, now, emit); err != nil {
			return err
		}
	}
	return nil
}

func visitIngestionPartition(ctx context.Context, spools []*ingestionSpool, i int, previous map[string]time.Time, now time.Time, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	records := map[string]*Record{}
	for _, s := range spools {
		if err := s.loadPartition(ctx, i, records); err != nil {
			return err
		}
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := records[id]
		applyDebianStatusMarkers(r)
		if added, exists := previous[id]; exists {
			r.AddedAt = added
		} else {
			r.AddedAt = now
		}
		r.LastSeenAt = now
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

// Native negative/uncertain status applies to the package and release even
// when OSV supplies different ranges. Preserve both entries, extending the
// native metadata precedence used by Merge beyond identical affected keys.
func applyDebianStatusMarkers(r *Record) {
	if !nativeAffectedSource("Debian", r.Source) {
		return
	}
	type key struct{ ecosystem, name string }
	markers := map[key]string{}
	for _, a := range r.Affected {
		if BaseEcosystem(a.Ecosystem) != "Debian" || len(a.Ranges) != 0 || len(a.Versions) != 0 {
			continue
		}
		status, _ := a.Database["debian_status"].(string)
		if status == "not-affected" || status == "undetermined" {
			markers[key{a.Ecosystem, NormalizeName(a.Ecosystem, a.Package)}] = status
		}
	}
	for i := range r.Affected {
		a := &r.Affected[i]
		if status := markers[key{a.Ecosystem, NormalizeName(a.Ecosystem, a.Package)}]; status != "" {
			a.Database = mergeSpecificMaps(a.Database, map[string]any{"debian_status": status}, true)
		}
	}
}

func (s *ingestionSpool) loadPartition(ctx context.Context, i int, records map[string]*Record) error {
	path := filepath.Join(s.dir, fmt.Sprint(i))
	f, err := os.Open(path) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = f.Close()
	}()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 64<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return err
		}
		if !validID(r.ID) {
			return errors.New("invalid spooled advisory")
		}
		if existing := records[r.ID]; existing != nil {
			Merge(existing, &r)
		} else {
			records[r.ID] = &r
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// Ties between candidates are resolved by record ID, independently of feed
// completion or partition order. All CVSS entries of the winning record are
// retained so consumers that cannot score V4 can still use its V3/V2 entries.
type aliasSeverityCandidate struct {
	id       string
	rank     int
	severity []Severity
}
type aliasSeverityIndex map[string]aliasSeverityCandidate

func cvssTypeRank(typ string) int {
	switch typ {
	case "CVSS_V4":
		return 3
	case "CVSS_V3":
		return 2
	case "CVSS_V2":
		return 1
	}
	return 0
}

func recordCVEs(r *Record) []string {
	var ids []string
	for _, id := range append([]string{r.ID}, r.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && validID(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func betterAliasSeverity(a, b aliasSeverityCandidate) bool {
	return a.rank > b.rank || (a.rank > 0 && a.rank == b.rank && a.id < b.id)
}

func (index aliasSeverityIndex) add(r *Record) {
	ids := recordCVEs(r)
	if len(ids) == 0 {
		return
	}
	candidate := aliasSeverityCandidate{id: r.ID}
	add := func(entries []Severity) {
		for _, entry := range entries {
			rank := cvssTypeRank(entry.Type)
			if rank == 0 || strings.TrimSpace(entry.Score) == "" {
				continue
			}
			candidate.rank = max(candidate.rank, rank)
			found := false
			for _, old := range candidate.severity {
				if old == entry {
					found = true
					break
				}
			}
			if !found {
				candidate.severity = append(candidate.severity, entry)
			}
		}
	}
	add(r.Severity)
	for _, affected := range r.Affected {
		add(affected.Severity)
	}
	if candidate.rank == 0 {
		return
	}
	sort.Slice(candidate.severity, func(i, j int) bool {
		a, b := candidate.severity[i], candidate.severity[j]
		if a.Type != b.Type {
			return cvssTypeRank(a.Type) > cvssTypeRank(b.Type)
		}
		return a.Score < b.Score
	})
	for _, id := range ids {
		if betterAliasSeverity(candidate, index[id]) {
			index[id] = candidate
		}
	}
}

func (index aliasSeverityIndex) apply(r *Record) {
	// Existing record severity already supplies the fallback for affected
	// entries without their own severity; preserve that effective rating.
	if len(r.Severity) != 0 {
		return
	}
	var best aliasSeverityCandidate
	for _, id := range recordCVEs(r) {
		if candidate := index[id]; betterAliasSeverity(candidate, best) {
			best = candidate
		}
	}
	if best.rank == 0 {
		return
	}
	r.Severity = append([]Severity(nil), best.severity...)
	for i := range r.Affected {
		if len(r.Affected[i].Severity) == 0 {
			r.Affected[i].Severity = append([]Severity(nil), best.severity...)
		}
	}
	if r.Database == nil {
		r.Database = map[string]any{}
	}
	r.Database["severity_source"] = "alias:" + best.id
}
