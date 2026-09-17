package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// ErrIDLookupUnsupported means the supplied Store does not implement the
// optional advisory-ID lookup capability. Existing Store implementations and
// matcher test doubles need not add a method to the public Store interface.
var ErrIDLookupUnsupported = errors.New("database does not support advisory ID lookup")

type idLookupStore interface {
	lookupID(string) ([]Record, error)
}

// LookupID returns complete advisory records matching an exact record ID or
// alias. Results are unique by record ID and sorted by ID. The returned records
// belong to the caller and may be annotated without changing the open database.
func LookupID(store Store, id string) ([]Record, error) {
	return LookupIDContext(context.Background(), store, id)
}

func LookupIDContext(ctx context.Context, store Store, id string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("advisory ID is required")
	}
	if reader, ok := store.(interface {
		lookupIDContext(context.Context, string) ([]Record, error)
	}); ok {
		return reader.lookupIDContext(ctx, id)
	}
	reader, ok := store.(idLookupStore)
	if !ok {
		return nil, ErrIDLookupUnsupported
	}
	records, err := reader.lookupID(id)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *sqliteStore) lookupID(id string) ([]Record, error) {
	return s.lookupIDContext(context.Background(), id)
}

func (s *sqliteStore) lookupIDContext(ctx context.Context, id string) (out []Record, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("database is unavailable")
	}
	defer func() {
		if changed := s.checkUnmodified(); changed != nil {
			out, err = nil, errors.Join(err, changed)
		}
	}()
	rows, err := s.conn.QueryContext(ctx, `SELECT json FROM records WHERE id=? OR id IN
 (SELECT record_id FROM aliases WHERE alias=?) ORDER BY id`, id, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = rows.Close()
	}()
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if len(data) >= 64<<20 {
			return nil, errors.New("SQLite advisory exceeds 64 MiB")
		}
		var record Record
		if err = decodeSQLiteRecord(data, &record); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *diskStore) lookupID(id string) ([]Record, error) {
	return s.lookupIDContext(context.Background(), id)
}

func (s *diskStore) lookupIDContext(ctx context.Context, id string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("database is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("database is closed")
	}
	// Use pinned file descriptors, not paths below s.dir: an update may have
	// replaced that directory since this reader verified and opened its snapshot.
	ecosystems := make([]string, 0, len(s.files))
	for eco := range s.files {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)
	found := map[string]Record{}
	collect := func(record *Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		matched := record.ID == id
		for _, alias := range record.Aliases {
			matched = matched || alias == id
		}
		if matched {
			if _, exists := found[record.ID]; !exists {
				found[record.ID] = *record
			}
		}
		return nil
	}
	for _, eco := range ecosystems {
		if cached := s.loaded[eco]; cached != nil {
			for i := range cached.records {
				if err := collect(&cached.records[i]); err != nil {
					return nil, err
				}
			}
			continue
		}
		// The shared reader applies exactly the existing per-record and expanded
		// index size bounds. Only matching records are kept in memory here.
		records := s.files[eco][1]
		if err := readRecordsReader(contextReader{ctx: ctx, r: io.NewSectionReader(records, 0, 1<<63-1)}, collect); err != nil {
			return nil, err
		}
	}
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Record
	for _, id := range ids {
		out = append(out, found[id])
	}
	if len(out) == 0 {
		return nil, nil
	}
	// Cached records can contain mutable maps and slices; match Lookup's
	// defensive-copy behavior while preserving the entire current Record model.
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var cloned []Record
	if err = json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloned, nil
}
