package vulndb

import (
	"bytes"
	"compress/zlib"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

type sqliteStore struct {
	db              *sql.DB
	conn            *sql.Conn
	meta            Meta
	snapshot        string
	releaseSnapshot func() error
	source          *catalogFile
	closeOnce       sync.Once
	closeErr        error
}

// ErrUnsupportedCatalog reports an installed catalog whose on-disk format
// this binary cannot read; a fresh `bscan db update` rebuilds it.
var ErrUnsupportedCatalog = errors.New("unsupported catalog format")

func openSQLiteSnapshot(dir string, m Meta, expectedDigest string) (Store, error) {
	return openSQLiteSnapshotContext(context.Background(), dir, m, expectedDigest)
}

func openSQLiteSnapshotContext(ctx context.Context, dir string, m Meta, expectedDigest string) (Store, error) {
	return openSQLiteSnapshotOptionsContext(ctx, dir, m, expectedDigest, Options{Isolation: "copy"}, nil)
}

func openSQLiteSnapshotOptionsContext(ctx context.Context, dir string, m Meta, expectedDigest string, opts Options, source *catalogFile) (Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mode, err := opts.isolationMode()
	if err != nil {
		return nil, err
	}
	snapshot, path := "", filepath.Join(dir, SQLiteFileName)
	cleanup := func() error { return nil }
	if source != nil {
		if err := source.check("catalog changed during verification"); err != nil {
			return nil, err
		}
		path = source.path()
	}
	if mode != "none" {
		var err error
		snapshot, cleanup, err = newReaderSnapshot(filepath.Dir(dir))
		if err != nil {
			return nil, err
		}
		source := path
		path = filepath.Join(snapshot, SQLiteFileName)
		isolated, err := isolateSQLiteContext(ctx, source, path, mode == "copy")
		if err != nil {
			cleanup()
			return nil, err
		}
		if !isolated {
			if err := cleanup(); err != nil {
				return nil, err
			}
			snapshot, path = "", source
			cleanup = func() error { return nil }
		} else if mode == "copy" {
			digest, err := hashFileContext(ctx, path)
			if err != nil {
				cleanup()
				return nil, err
			}
			if digest != expectedDigest {
				cleanup()
				return nil, errors.New("SQLite catalog changed while its verified snapshot was being created")
			}
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteURI(absolute, true))
	if err != nil {
		cleanup()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (Store, error) { db.Close(); cleanup(); return nil, err }
	conn, err := db.Conn(ctx)
	if err != nil {
		return fail(err)
	}
	fail = func(err error) (Store, error) { conn.Close(); db.Close(); cleanup(); return nil, err }
	// Limits belong to a physical connection, so all queries use this pinned
	// connection for its full lifetime, including advisory-ID lookups.
	if _, err = sqlite.Limit(conn, sqlitelib.SQLITE_LIMIT_LENGTH, 64<<20); err != nil {
		return fail(err)
	}
	if _, err = sqlite.Limit(conn, sqlitelib.SQLITE_LIMIT_SQL_LENGTH, 1<<20); err != nil {
		return fail(err)
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;"); err != nil {
		return fail(err)
	}
	var schema int
	if err = conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schema); err != nil {
		return fail(err)
	}
	if schema != SQLiteSchemaVersion {
		return fail(fmt.Errorf("%w: SQLite catalog schema %d; run bscan db update", ErrUnsupportedCatalog, schema))
	}
	if err = validateSQLiteSchemaContext(ctx, conn); err != nil {
		return fail(err)
	}
	var encoding string
	if err = conn.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='record_encoding'").Scan(&encoding); err != nil || encoding != sqliteRecordEncoding {
		return fail(fmt.Errorf("%w: SQLite record encoding; run bscan db update", ErrUnsupportedCatalog))
	}
	var stored string
	if err = conn.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='meta'").Scan(&stored); err != nil {
		return fail(err)
	}
	var embedded Meta
	if err = json.Unmarshal([]byte(stored), &embedded); err != nil {
		return fail(err)
	}
	a, _ := json.Marshal(m)
	b, _ := json.Marshal(embedded)
	if string(a) != string(b) {
		return fail(errors.New("SQLite metadata does not match catalog manifest metadata"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if source != nil {
		if err := source.check("catalog changed during verification"); err != nil {
			return fail(err)
		}
		if snapshot != "" {
			source = nil
		}
	}
	return &sqliteStore{db: db, conn: conn, meta: m, snapshot: snapshot, releaseSnapshot: cleanup, source: source}, nil
}

func cloneOrCopySQLite(src, dst string) error {
	return cloneOrCopySQLiteContext(context.Background(), src, dst)
}

func cloneOrCopySQLiteContext(ctx context.Context, src, dst string) error {
	_, err := isolateSQLiteContext(ctx, src, dst, true)
	return err
}

// The caller holds the database lock from verification until isolation finishes.
// Auto never falls back to a full copy; a failed clone retains an in-place reader.
func isolateSQLiteContext(ctx context.Context, src, dst string, allowCopy bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return false, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	cloneErr := cloneSQLiteFile(out, in)
	closeErr := out.Close()
	if closeErr != nil {
		return false, closeErr
	}
	if cloneErr != nil {
		if !allowCopy {
			return false, errors.Join(os.Remove(dst), ctx.Err())
		}
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		if err := copySQLiteFileContext(ctx, in, dst); err != nil {
			return false, err
		}
	}
	after, err := os.Stat(dst)
	if err != nil {
		return false, err
	}
	if after.Size() != before.Size() {
		return false, errors.New("SQLite snapshot size does not match source")
	}
	return true, ctx.Err()
}

// Complete fallback copies in a temporary file beside the snapshot destination.
// This keeps the large copy on the same filesystem and publishes it atomically.
func copySQLiteFileContext(ctx context.Context, in io.Reader, dst string) error {
	out, err := os.CreateTemp(filepath.Dir(dst), ".sqlite-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	_, copyErr := io.Copy(out, contextReader{ctx: ctx, r: in})
	if err = errors.Join(copyErr, out.Close(), ctx.Err()); err != nil {
		return err
	}
	return os.Rename(out.Name(), dst)
}

func (s *sqliteStore) Meta() (Meta, error) {
	b, _ := json.Marshal(s.meta)
	var m Meta
	_ = json.Unmarshal(b, &m)
	return m, nil
}
func (s *sqliteStore) Ecosystems() ([]string, error) {
	return append([]string(nil), s.meta.Ecosystems...), nil
}
func (s *sqliteStore) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.conn.Close(), s.db.Close(), s.checkUnmodified())
		if s.source != nil {
			s.closeErr = errors.Join(s.closeErr, s.source.file.Close())
		}
		s.closeErr = errors.Join(s.closeErr, s.releaseSnapshot())
	})
	return s.closeErr
}
func (s *sqliteStore) Lookup(ecosystem, name string) ([]Record, error) {
	return s.LookupContext(context.Background(), ecosystem, name)
}

func (s *sqliteStore) LookupContext(ctx context.Context, ecosystem, name string) ([]Record, error) {
	var out []Record
	err := s.LookupFunc(ctx, ecosystem, name, func(r *Record) error { out = append(out, *r); return nil })
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LookupFunc visits independently owned records in advisory-ID order. The
// callback must not issue another query on this store's pinned connection.
// Callers must discard partial results if the final integrity check fails.
func (s *sqliteStore) LookupFunc(ctx context.Context, ecosystem, name string, fn func(*Record) error) (err error) {
	defer func() {
		if changed := s.checkUnmodified(); changed != nil {
			err = errors.Join(err, changed)
		}
	}()
	rows, err := s.conn.QueryContext(ctx, `SELECT json FROM records WHERE id IN
 (SELECT record_id FROM package_affected WHERE base_ecosystem=? AND name=?) ORDER BY id`, BaseEcosystem(ecosystem), NormalizeName(ecosystem, name))
	if err != nil {
		return err
	}
	defer rows.Close()
	decoder := sqliteReadDecoders.Get().(*sqliteReadDecoder)
	defer func() {
		decoder.input.Reset(nil)
		// Do not retain unusually large advisory buffers in the pool.
		if decoder.output.Cap() <= 1<<20 {
			sqliteReadDecoders.Put(decoder)
		}
	}()
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return err
		}
		if len(b) >= 64<<20 {
			return errors.New("SQLite advisory exceeds 64 MiB")
		}
		var r Record
		if err = decoder.decode(b, &r); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = fn(&r); err != nil {
			return err
		}
	}
	return errors.Join(rows.Err(), ctx.Err())
}

// Imported catalogs must expose the ordinary tables produced by the current SQLite schema.
// Reject views, virtual tables and generated columns before selecting advisory
// data, so a matching name cannot disguise executable expressions or huge blobs.
func validateSQLiteSchema(conn *sql.Conn) error {
	return validateSQLiteSchemaContext(context.Background(), conn)
}

func validateSQLiteSchemaContext(ctx context.Context, conn *sql.Conn) error {
	required := map[string][]string{
		"records":             {"id", "summary", "details", "source", "published_at", "modified_at", "withdrawn_at", "added_at", "last_seen_at", "details_truncated", "json"},
		"package_affected":    {"base_ecosystem", "name", "release", "record_id"},
		"aliases":             {"alias", "record_id"},
		"record_sources":      {"record_id", "source", "url"},
		"sources":             {"id", "name", "url", "ecosystems_json", "etag", "last_modified", "sha256", "bytes", "records", "fetched_at", "error"},
		"advisory_references": {"record_id", "ordinal", "type", "url"},
		"affected":            {"id", "record_id", "ordinal", "ecosystem", "base_ecosystem", "release", "package_name", "normalized_name", "purl", "ecosystem_specific_json", "database_specific_json", "versions_blob"},
		"affected_ranges":     {"id", "affected_id", "range_type", "repo", "ordinal"},
		"range_events":        {"range_id", "ordinal", "introduced", "fixed", "last_affected", "limit_version"},
		"severities":          {"record_id", "ordinal", "type", "score"},
		"metadata":            {"key", "value"},
	}
	for name, columns := range required {
		var kind string
		if err := conn.QueryRowContext(ctx, "SELECT type FROM pragma_table_list WHERE schema='main' AND name=?", name).Scan(&kind); err != nil {
			return fmt.Errorf("SQLite required table %s unavailable: %w", name, err)
		}
		if kind != "table" {
			return fmt.Errorf("SQLite %s must be an ordinary table", name)
		}
		rows, err := conn.QueryContext(ctx, "SELECT name,hidden FROM pragma_table_xinfo(?) ORDER BY cid", name)
		if err != nil {
			return err
		}
		var got []string
		for rows.Next() {
			var col string
			var hidden int
			if err = rows.Scan(&col, &hidden); err != nil {
				rows.Close()
				return err
			}
			if hidden != 0 {
				rows.Close()
				return fmt.Errorf("SQLite %s contains generated or hidden columns", name)
			}
			got = append(got, col)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if strings.Join(got, "\x00") != strings.Join(columns, "\x00") {
			return fmt.Errorf("SQLite %s has unexpected columns", name)
		}
	}
	return nil
}

// Reader copies (including the full-copy fallback) stay on the source filesystem
// in a private sibling directory, instead of spilling into a global temp volume.
func newReaderSnapshot(parent string) (string, func() error, error) {
	// Serialize publishing a directory and its owner lock with stale collection.
	unlock, err := acquireReaderGuard(filepath.Join(parent, ".bscan-db-readers.lock"))
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	if err = removeStaleReaderSnapshots(parent); err != nil {
		return "", nil, err
	}
	snapshot, err := os.MkdirTemp(parent, ".bscan-db-reader-")
	if err != nil {
		return "", nil, err
	}
	ownerUnlock, err := acquireDatabaseLock(filepath.Join(snapshot, "owner.lock"))
	if err != nil {
		os.RemoveAll(snapshot)
		return "", nil, err
	}
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() { cleanupErr = os.RemoveAll(snapshot); ownerUnlock() })
		return cleanupErr
	}
	return snapshot, cleanup, nil
}

func (s *sqliteStore) checkUnmodified() error {
	if s.source == nil {
		return nil
	}
	return s.source.check("catalog modified during read")
}

// Each lookup exclusively owns its decoder. Reset reuses flate's 32 KiB
// dictionary and the expanded JSON buffer while preserving checksum and caps.
type sqliteReadDecoder struct {
	input  bytes.Reader
	output bytes.Buffer
	reader io.ReadCloser
}

var sqliteReadDecoders = sync.Pool{New: func() any { return new(sqliteReadDecoder) }}

func (d *sqliteReadDecoder) decode(data []byte, record *Record) error {
	d.input.Reset(data)
	var err error
	if d.reader == nil {
		d.reader, err = zlib.NewReader(&d.input)
	} else {
		err = d.reader.(zlib.Resetter).Reset(&d.input, nil)
	}
	if err != nil {
		return fmt.Errorf("invalid compressed SQLite advisory: %w", err)
	}
	defer d.reader.Close()
	d.output.Reset()
	_, err = d.output.ReadFrom(io.LimitReader(d.reader, 64<<20))
	if err != nil {
		return fmt.Errorf("invalid compressed SQLite advisory: %w", err)
	}
	if d.output.Len() >= 64<<20 {
		return errors.New("SQLite advisory exceeds expanded size limit")
	}
	return json.Unmarshal(d.output.Bytes(), record)
}
