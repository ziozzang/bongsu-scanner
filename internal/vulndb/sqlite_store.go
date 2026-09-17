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

// Injectable resource limits; production defaults remain 64 MiB.
var sqliteMaxRowBytes = 64 << 20
var sqliteMaxExpandedBytes int64 = 64 << 20

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
			// Cleanup only; read errors or the primary operation error are handled separately.
			_ = cleanup()
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
				// Cleanup only; read errors or the primary operation error are handled separately.
				_ = cleanup()
				return nil, err
			}
			if digest != expectedDigest {
				// Cleanup only; read errors or the primary operation error are handled separately.
				_ = cleanup()
				return nil, errors.New("SQLite catalog changed while its verified snapshot was being created")
			}
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = cleanup()
		return nil, err
	}
	db, err := sql.Open("sqlite", sqliteURI(absolute, true))
	if err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = cleanup()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (Store, error) { // Cleanup only; read errors or the primary operation error are handled separately.
		_ = db.Close() // Cleanup only; read errors or the primary operation error are handled separately.
		_ = cleanup()
		return nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fail(err)
	}
	fail = func(err error) (Store, error) { // Cleanup only; read errors or the primary operation error are handled separately.
		_ = conn.Close() // Cleanup only; read errors or the primary operation error are handled separately.
		_ = db.Close()   // Cleanup only; read errors or the primary operation error are handled separately.
		_ = cleanup()
		return nil, err
	}
	// Limits belong to a physical connection, so all queries use this pinned
	// connection for its full lifetime, including advisory-ID lookups.
	if _, err = sqlite.Limit(conn, sqlitelib.SQLITE_LIMIT_LENGTH, sqliteMaxRowBytes); err != nil {
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

// The caller holds the database lock from verification until isolation finishes.
// Auto never falls back to a full copy; a failed clone retains an in-place reader.
func isolateSQLiteContext(ctx context.Context, src, dst string, allowCopy bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	in, err := os.Open(src) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
	if err != nil {
		return false, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = in.Close()
	}()
	before, err := in.Stat()
	if err != nil {
		return false, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600) // #nosec G304 -- Catalog/cache paths are constructed under the caller-selected database or staging directory.
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
	defer func() {
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.Remove(out.Name())
	}()
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
func (s *sqliteStore) LookupFunc(ctx context.Context, ecosystem, name string, fn func(*Record) error) error {
	return s.lookupFunc(ctx, ecosystem, name, false, fn)
}

// LookupMatchingFunc borrows the Record and its outer Affected slice until the
// callback returns. Nested values are independently owned: callers may retain
// identities, text, and copies of individual Affected values. This lets the
// matcher discard one decoded advisory before reading the next without repeated
// allocation of large outer affected arrays. The ordinary visitor stays owning.
func (s *sqliteStore) LookupMatchingFunc(ctx context.Context, ecosystem, name string, fn func(*Record) error) error {
	return s.lookupFunc(ctx, ecosystem, name, true, fn)
}

func (s *sqliteStore) lookupFunc(ctx context.Context, ecosystem, name string, borrowed bool, fn func(*Record) error) (err error) {
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
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = rows.Close()
	}()
	decoder := takeSQLiteReadDecoder()
	defer func() { releaseSQLiteReadDecoder(decoder) }()
	var scratch []Affected
	for rows.Next() {
		var b sql.RawBytes
		if err = rows.Scan(&b); err != nil {
			return err
		}
		if len(b) >= 64<<20 {
			return errors.New("SQLite advisory exceeds 64 MiB")
		}
		var r Record
		if borrowed {
			clear(scratch)
			r.Affected = scratch[:0]
		}
		if err = decoder.decode(b, &r); err != nil {
			return err
		}
		if borrowed {
			scratch = r.Affected
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

func validateSQLiteSchemaContext(ctx context.Context, conn *sql.Conn) error {
	required := map[string][]string{
		"cpe_matches":         {"vendor", "product", "record_id"},
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
				// Cleanup only; read errors or the primary operation error are handled separately.
				_ = rows.Close()
				return err
			}
			if hidden != 0 {
				// Cleanup only; read errors or the primary operation error are handled separately.
				_ = rows.Close()
				return fmt.Errorf("SQLite %s contains generated or hidden columns", name)
			}
			got = append(got, col)
		}
		err = rows.Err()
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = rows.Close()
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
		// Best-effort removal of temporary state; preserve the operation result.
		_ = os.RemoveAll(snapshot)
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

// A bounded pool prevents one decoder per scheduler P (and an occasional
// oversized advisory buffer) from remaining resident after concurrent lookups.
var sqliteReadDecoders = make(chan *sqliteReadDecoder, 2)

func takeSQLiteReadDecoder() *sqliteReadDecoder {
	select {
	case d := <-sqliteReadDecoders:
		return d
	default:
		return new(sqliteReadDecoder)
	}
}
func releaseSQLiteReadDecoder(d *sqliteReadDecoder) {
	d.input.Reset(nil)
	if d.output.Cap() > 64<<10 {
		d.output = bytes.Buffer{}
	} else {
		d.output.Reset()
	}
	select {
	case sqliteReadDecoders <- d:
	default:
	}
}

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
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = d.reader.Close()
	}()
	d.output.Reset()
	_, err = d.output.ReadFrom(io.LimitReader(d.reader, sqliteMaxExpandedBytes))
	if err != nil {
		return fmt.Errorf("invalid compressed SQLite advisory: %w", err)
	}
	if int64(d.output.Len()) >= sqliteMaxExpandedBytes {
		return errors.New("SQLite advisory exceeds expanded size limit")
	}
	return json.Unmarshal(d.output.Bytes(), record)
}

// LookupCPE uses the vendor/product primary key and returns independently owned records.
func (s *sqliteStore) LookupCPE(vendor, product string) ([]Record, error) {
	return s.LookupCPEContext(context.Background(), vendor, product)
}
func (s *sqliteStore) LookupCPEContext(ctx context.Context, vendor, product string) (out []Record, err error) {
	defer func() {
		if changed := s.checkUnmodified(); changed != nil {
			out = nil
			err = errors.Join(err, changed)
		}
	}()
	vendorAttr, vendorOK := ParseCPEAttribute(vendor)
	productAttr, productOK := ParseCPEAttribute(product)
	if !vendorOK || !productOK || vendorAttr.Kind != CPELiteral || productAttr.Kind != CPELiteral {
		return nil, nil
	}
	rows, err := s.conn.QueryContext(ctx, `SELECT json FROM records WHERE id IN
 (SELECT record_id FROM cpe_matches WHERE vendor=? AND product=?) ORDER BY id`, vendorAttr.Value, productAttr.Value)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = rows.Close()
	}()
	decoder := takeSQLiteReadDecoder()
	defer releaseSQLiteReadDecoder(decoder)
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if len(b) >= 64<<20 {
			return nil, errors.New("SQLite advisory exceeds 64 MiB")
		}
		var r Record
		if err = decoder.decode(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err = errors.Join(rows.Err(), ctx.Err()); err != nil {
		return nil, err
	}
	return out, nil
}
