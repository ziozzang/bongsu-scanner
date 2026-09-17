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
	"net/url"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
	_ "modernc.org/sqlite"
)

// SQLiteFileName is the portable primary catalog.
const SQLiteFileName = "advisories.sqlite"

// SQLiteSchemaVersion tracks the SQLite layout independently of the outer
// catalog envelope (SchemaVersion), which also governs feed caches and updates.
const SQLiteSchemaVersion = 7
const sqliteRecordEncoding = "zlib-json-v1"

const sqliteSchema = `
PRAGMA user_version = 7;
CREATE TABLE records (
 id TEXT PRIMARY KEY NOT NULL,
 summary TEXT NOT NULL,
 details TEXT NOT NULL,
 source TEXT NOT NULL,
 published_at TEXT,
 modified_at TEXT,
 withdrawn_at TEXT,
 added_at TEXT,
 last_seen_at TEXT,
 details_truncated INTEGER NOT NULL,
 json BLOB NOT NULL
);
CREATE TABLE package_affected (
 base_ecosystem TEXT NOT NULL,
 name TEXT NOT NULL,
 release TEXT NOT NULL,
 record_id TEXT NOT NULL REFERENCES records(id),
 PRIMARY KEY(base_ecosystem, name, release, record_id)
) WITHOUT ROWID;
CREATE TABLE cpe_matches (
 vendor TEXT NOT NULL,
 product TEXT NOT NULL,
 record_id TEXT NOT NULL REFERENCES records(id),
 PRIMARY KEY(vendor, product, record_id)
) WITHOUT ROWID;
CREATE TABLE aliases (
 alias TEXT NOT NULL,
 record_id TEXT NOT NULL REFERENCES records(id),
 PRIMARY KEY(alias, record_id)
) WITHOUT ROWID;
CREATE TABLE record_sources (
 record_id TEXT NOT NULL REFERENCES records(id),
 source TEXT NOT NULL,
 url TEXT NOT NULL,
 PRIMARY KEY(record_id, source, url)
) WITHOUT ROWID;
CREATE TABLE sources (
 id INTEGER PRIMARY KEY,
 name TEXT NOT NULL,
 url TEXT NOT NULL,
 ecosystems_json TEXT NOT NULL,
 etag TEXT,
 last_modified TEXT,
 sha256 TEXT,
 bytes INTEGER NOT NULL,
 records INTEGER NOT NULL,
 fetched_at TEXT,
 error TEXT
);
CREATE UNIQUE INDEX source_feeds ON sources(name, url);
CREATE TABLE advisory_references (
 record_id TEXT NOT NULL REFERENCES records(id),
 ordinal INTEGER NOT NULL,
 type TEXT NOT NULL,
 url TEXT NOT NULL,
 PRIMARY KEY(record_id, ordinal)
) WITHOUT ROWID;
CREATE TABLE affected (
 id INTEGER PRIMARY KEY,
 record_id TEXT NOT NULL REFERENCES records(id),
 ordinal INTEGER NOT NULL,
 ecosystem TEXT NOT NULL,
 base_ecosystem TEXT NOT NULL,
 release TEXT NOT NULL,
 package_name TEXT NOT NULL,
 normalized_name TEXT NOT NULL,
 purl TEXT,
 ecosystem_specific_json TEXT NOT NULL,
 database_specific_json TEXT NOT NULL,
 versions_blob BLOB NOT NULL
);
CREATE TABLE affected_ranges (
 id INTEGER PRIMARY KEY,
 affected_id INTEGER NOT NULL REFERENCES affected(id),
 range_type TEXT NOT NULL,
 repo TEXT,
 ordinal INTEGER NOT NULL
);
CREATE TABLE range_events (
 range_id INTEGER NOT NULL REFERENCES affected_ranges(id),
 ordinal INTEGER NOT NULL,
 introduced TEXT,
 fixed TEXT,
 last_affected TEXT,
 limit_version TEXT,
 PRIMARY KEY(range_id, ordinal)
) WITHOUT ROWID;
CREATE TABLE severities (
 record_id TEXT NOT NULL REFERENCES records(id),
 ordinal INTEGER NOT NULL,
 type TEXT NOT NULL,
 score TEXT NOT NULL,
 PRIMARY KEY(record_id, ordinal)
) WITHOUT ROWID;
CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
`

// Build secondary indexes once, after their rows are loaded. The final schema
// and all reader queries remain unchanged.
const sqliteIndexes = `
CREATE INDEX package_lookup ON package_affected(base_ecosystem, name, record_id);
CREATE INDEX source_records ON record_sources(source, url, record_id);
CREATE INDEX affected_record ON affected(record_id, ordinal);
CREATE INDEX affected_package ON affected(base_ecosystem, normalized_name, record_id);
CREATE INDEX ranges_affected ON affected_ranges(affected_id, ordinal);
`

func sqliteURI(path string, immutable bool) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := url.Values{}
	if immutable {
		q.Set("mode", "ro")
		q.Set("immutable", "1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// affectedIndexName returns the normalized package identity used by both
// persistent catalog indexes. A valid PURL can supply the name when an
// affected entry omits package.name, but a known PURL ecosystem must agree
// with the affected ecosystem before it contributes an index row.
func affectedIndexName(a Affected) (string, bool) {
	eco := BaseEcosystem(a.Ecosystem)
	if eco == "" {
		return "", false
	}
	name := strings.TrimSpace(a.Package)
	if raw := strings.TrimSpace(a.PURL); raw != "" {
		parsed, err := purl.Parse(raw)
		if err == nil {
			purlEco := PURLTypeToEcosystem(parsed.Type, parsed.Namespace)
			if purlEco != "" && BaseEcosystem(purlEco) != eco {
				return "", false
			}
			if name == "" && purlEco != "" {
				name = parsed.FullName()
			}
		}
	}
	name = NormalizeName(eco, name)
	return name, name != ""
}

func buildSQLite(ctx context.Context, dir string, records map[string]*Record, meta *Meta) error {
	return buildSQLiteStream(ctx, dir, func(emit Emit) error {
		ids := make([]string, 0, len(records))
		for id := range records {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r := records[id]
			if r == nil || r.ID != id {
				return fmt.Errorf("invalid catalog record %q", id)
			}
			if err := emit(r); err != nil {
				return err
			}
		}
		return nil
	}, meta)
}

// buildSQLiteStream retains only the current record and bounded insert buffers.
// The producer must emit each ID once in a deterministic order.
func buildSQLiteStream(ctx context.Context, dir string, visit func(Emit) error, meta *Meta) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := filepath.Abs(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", sqliteURI(path, false))
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = db.Close()
	}()
	db.SetMaxOpenConns(1)
	// This file is private staging output: failed builds are discarded, and
	// the completed file is closed, hashed and verified before installation.
	if _, err = db.ExecContext(ctx, "PRAGMA page_size=16384; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-131072;"); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		// Rollback is cleanup after failure or a checked Commit.
		_ = tx.Rollback()
	}()
	if _, err = tx.ExecContext(ctx, sqliteSchema); err != nil {
		return err
	}
	queries := map[string]string{
		"cpe":       "INSERT OR IGNORE INTO cpe_matches(vendor,product,record_id) VALUES(?,?,?)",
		"record":    "INSERT INTO records(id,summary,details,source,published_at,modified_at,withdrawn_at,added_at,last_seen_at,details_truncated,json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		"package":   "INSERT OR IGNORE INTO package_affected(base_ecosystem,name,release,record_id) VALUES(?,?,?,?)",
		"alias":     "INSERT OR IGNORE INTO aliases(alias,record_id) VALUES(?,?)",
		"source":    "INSERT OR IGNORE INTO record_sources(record_id,source,url) VALUES(?,?,?)",
		"reference": "INSERT INTO advisory_references(record_id,ordinal,type,url) VALUES(?,?,?,?)",
		"affected":  "INSERT INTO affected(record_id,ordinal,ecosystem,base_ecosystem,release,package_name,normalized_name,purl,ecosystem_specific_json,database_specific_json,versions_blob) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
		"range":     "INSERT INTO affected_ranges(affected_id,range_type,repo,ordinal) VALUES(?,?,?,?)",
		"event":     "INSERT INTO range_events(range_id,ordinal,introduced,fixed,last_affected,limit_version) VALUES(?,?,?,?,?,?)",
		"severity":  "INSERT INTO severities(record_id,ordinal,type,score) VALUES(?,?,?,?)",
	}
	statements := map[string]*sql.Stmt{}
	defer func() {
		for _, s := range statements {
			_ = s.Close()
		}
	}()
	for key, query := range queries {
		stmt, err := tx.PrepareContext(ctx, query)
		if err != nil {
			return err
		}
		statements[key] = stmt
	}
	insert := func(key string, args ...any) (sql.Result, error) { return statements[key].ExecContext(ctx, args...) }
	batches := map[string]*sqliteBatch{}
	defer func() {
		for _, batch := range batches {
			batch.close()
		}
	}()
	for key, columns := range map[string]int{"package": 4, "alias": 2, "source": 3, "reference": 4, "event": 6, "severity": 4} {
		prefix, _, _ := strings.Cut(queries[key], " VALUES")
		batch, err := newSQLiteBatch(ctx, tx, prefix+" VALUES", columns)
		if err != nil {
			return err
		}
		batches[key] = batch
	}
	ecosystems := map[string]bool{}
	count := 0
	err = visitCompressedSQLiteRecords(ctx, visit, func(r *Record, b []byte, versions [][]byte) error {
		id := r.ID
		count++
		// Full details live only in records.json; retain the empty SQL column for
		// browsing compatibility and preserve the upstream truncation flag.
		if _, err = insert("record", id, r.Summary, "", r.Source, nullableText(r.Published), nullableText(r.Modified), nullableText(r.Withdrawn), nullableTime(r.AddedAt), nullableTime(r.LastSeenAt), r.DetailsTruncated, b); err != nil {
			return err
		}
		knownSources := map[string]bool{}
		for _, source := range r.Provenance {
			if err = batches["source"].add(id, source.Name, source.URL); err != nil {
				return err
			}
			knownSources[source.Name] = true
		}
		for _, source := range dedupeStrings(strings.Split(r.Source, ",")) {
			if !knownSources[source] {
				if err = batches["source"].add(id, source, ""); err != nil {
					return err
				}
			}
		}
		for _, alias := range dedupeStrings(r.Aliases) {
			if err = batches["alias"].add(alias, id); err != nil {
				return err
			}
		}
		for ordinal, ref := range r.References {
			if err = batches["reference"].add(id, ordinal, ref.Type, ref.URL); err != nil {
				return err
			}
		}
		for ordinal, severity := range r.Severity {
			if err = batches["severity"].add(id, ordinal, severity.Type, severity.Score); err != nil {
				return err
			}
		}
		for ordinal, a := range r.Affected {
			if a.Ecosystem == "CPE" {
				raw, _ := a.Database["cpe"].(string)
				attrs, ok := ParseCPE(raw)
				// The raw criteria also normalize records from older feed caches.
				if ok && attrs[1].Kind == CPELiteral && attrs[2].Kind == CPELiteral {
					if _, err = insert("cpe", attrs[1].Value, attrs[2].Value, id); err != nil {
						return err
					}
				}
			}
			eco := BaseEcosystem(a.Ecosystem)
			name, indexable := affectedIndexName(a)
			if eco != "" && indexable {
				ecosystems[a.Ecosystem] = true
				if err = batches["package"].add(eco, name, EcosystemRelease(a.Ecosystem), id); err != nil {
					return err
				}
			}
			specific, err := json.Marshal(a.Specific)
			if err != nil {
				return err
			}
			database, err := json.Marshal(a.Database)
			if err != nil {
				return err
			}
			result, err := insert("affected", id, ordinal, a.Ecosystem, eco, EcosystemRelease(a.Ecosystem), a.Package, name, nullableText(a.PURL), string(specific), string(database), versions[ordinal])
			if err != nil {
				return err
			}
			affectedID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			for rangeOrdinal, rg := range a.Ranges {
				result, err = insert("range", affectedID, rg.Type, nullableText(rg.Repo), rangeOrdinal)
				if err != nil {
					return err
				}
				rangeID, err := result.LastInsertId()
				if err != nil {
					return err
				}
				for index, event := range rg.Events {
					if err = batches["event"].add(rangeID, index, nullableText(event.Introduced), nullableText(event.Fixed), nullableText(event.LastAffected), nullableText(event.Limit)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, key := range []string{"package", "alias", "source", "reference", "event", "severity"} {
		if err = batches[key].flush(); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, sqliteIndexes); err != nil {
		return err
	}
	meta.SchemaVersion = SchemaVersion
	meta.Records = count
	meta.Ecosystems = nil
	for eco := range ecosystems {
		meta.Ecosystems = append(meta.Ecosystems, eco)
	}
	sort.Strings(meta.Ecosystems)
	for _, source := range meta.Sources {
		ecos, err := json.Marshal(source.Ecosystems)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT OR REPLACE INTO sources(name,url,ecosystems_json,etag,last_modified,sha256,bytes,records,fetched_at,error) VALUES(?,?,?,?,?,?,?,?,?,?)", source.Name, source.URL, string(ecos), nullableText(source.ETag), nullableText(source.LastMod), nullableText(source.SHA256), source.Bytes, source.Records, nullableTime(source.FetchedAt), nullableText(source.Error)); err != nil {
			return err
		}
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES('meta',?)", string(b)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES('record_encoding',?)", sqliteRecordEncoding); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return db.Close()
}

// Reuse the compressor workspace across hundreds of thousands of records.
var sqliteCompressors = sync.Pool{New: func() any { return zlib.NewWriter(io.Discard) }}

func compressSQLiteJSON(data []byte) ([]byte, error) {
	var b bytes.Buffer
	zw := sqliteCompressors.Get().(*zlib.Writer)
	defer sqliteCompressors.Put(zw)
	zw.Reset(&b)
	if _, err := zw.Write(data); err != nil {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decodeSQLiteRecord is shared by package and ID lookup. Any other reader of
// records.json (including visitStoreRecords) must use this bounded decoder.
func decodeSQLiteRecord(data []byte, record *Record) error {
	return decodeSQLiteRecordBounded(data, record, 64<<20)
}

func decodeSQLiteRecordBounded(data []byte, record *Record, limit int64) error {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid compressed SQLite advisory: %w", err)
	}
	defer func() {
		// Cleanup only; read errors or the primary operation error are handled separately.
		_ = zr.Close()
	}()
	b, err := io.ReadAll(io.LimitReader(zr, limit))
	if err != nil {
		return fmt.Errorf("invalid compressed SQLite advisory: %w", err)
	}
	if int64(len(b)) >= limit {
		return errors.New("SQLite advisory exceeds expanded size limit")
	}
	return json.Unmarshal(b, record)
}

// sqliteBatch amortizes database/sql argument conversion and VM setup while
// preserving every row, ordinal and foreign key check. Buffering is bounded.
type sqliteBatch struct {
	ctx     context.Context
	tx      *sql.Tx
	prefix  string
	columns int
	args    []any
	full    *sql.Stmt
}

const sqliteBatchRows = 128

func newSQLiteBatch(ctx context.Context, tx *sql.Tx, prefix string, columns int) (*sqliteBatch, error) {
	b := &sqliteBatch{ctx: ctx, tx: tx, prefix: prefix, columns: columns, args: make([]any, 0, sqliteBatchRows*columns)}
	var err error
	b.full, err = tx.PrepareContext(ctx, b.query(sqliteBatchRows))
	return b, err
}
func (b *sqliteBatch) query(rows int) string {
	row := "(" + strings.TrimSuffix(strings.Repeat("?,", b.columns), ",") + ")"
	return b.prefix + strings.TrimSuffix(strings.Repeat(row+",", rows), ",")
}
func (b *sqliteBatch) add(args ...any) error {
	b.args = append(b.args, args...)
	if len(b.args) == cap(b.args) {
		return b.flush()
	}
	return nil
}
func (b *sqliteBatch) flush() error {
	if len(b.args) == 0 {
		return b.ctx.Err()
	}
	var err error
	if len(b.args) == cap(b.args) {
		_, err = b.full.ExecContext(b.ctx, b.args...)
	} else {
		_, err = b.tx.ExecContext(b.ctx, b.query(len(b.args)/b.columns), b.args...)
	}
	clear(b.args)
	b.args = b.args[:0]
	return err
}
func (b *sqliteBatch) close() { _ = b.full.Close() }

// Compress on a bounded worker pool while SQLite consumes results in exactly
// producer order. Workers only access private JSON buffers; the producer keeps
// ownership of input records until completion. Cancellation joins all goroutines.
func visitCompressedSQLiteRecords(ctx context.Context, visit func(Emit) error, emit func(*Record, []byte, [][]byte) error) error {
	emptyVersions, err := compressSQLiteJSON([]byte("[]"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	type prepared struct {
		record   *Record
		data     []byte
		versions [][]byte
	}
	type job struct {
		records []prepared
		err     error
		done    chan struct{}
	}
	workers := min(4, runtime.GOMAXPROCS(0))
	jobs := make(chan *job, workers)
	ordered := make(chan *job, workers)
	result := make(chan error, 1)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for i := range j.records {
					if j.err = ctx.Err(); j.err != nil {
						break
					}
					p := &j.records[i]
					p.data, j.err = compressSQLiteJSON(p.data)
					if j.err != nil {
						break
					}
					for k, versions := range p.versions {
						if j.err = ctx.Err(); j.err != nil {
							break
						}
						if versions == nil {
							p.versions[k] = emptyVersions
							continue
						}
						p.versions[k], j.err = compressSQLiteJSON(versions)
						if j.err != nil {
							break
						}
					}
					if j.err != nil {
						break
					}
				}
				close(j.done)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		defer close(ordered)
		var pending []prepared
		var pendingBytes int
		dispatch := func() error {
			if len(pending) == 0 {
				return ctx.Err()
			}
			j := &job{records: pending, done: make(chan struct{})}
			select {
			case jobs <- j:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case ordered <- j:
			case <-ctx.Done():
				return ctx.Err()
			}
			pending, pendingBytes = nil, 0
			return nil
		}
		err := visit(func(r *Record) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if r == nil || !validID(r.ID) {
				return errors.New("invalid catalog record")
			}
			copyRecord := *r
			copyRecord.Affected = append(r.Affected[:0:0], r.Affected...)
			sortAffected(copyRecord.Affected)
			b, err := json.Marshal(&copyRecord)
			if err != nil {
				return err
			}
			// Retain the existing expanded row limit, including duplicated text.
			if len(b)+len(r.Summary)+len(r.Details)+len(r.Source)+len(r.Published)+len(r.Modified)+len(r.Withdrawn)+len(r.ID)+1024 >= 64<<20 {
				return errors.New("SQLite advisory row exceeds 64 MiB")
			}
			versions := make([][]byte, len(copyRecord.Affected))
			preparedBytes := len(b)
			for i, a := range copyRecord.Affected {
				if len(a.Versions) == 0 {
					continue
				}
				versions[i], err = json.Marshal(a.Versions)
				if err != nil {
					return err
				}
				preparedBytes += len(versions[i])
			}
			// Batch small records to amortize channel wakeups, but allow at most
			// one already-bounded large record to exceed the 4 MiB batch budget.
			if len(pending) > 0 && pendingBytes+preparedBytes > 4<<20 {
				if err := dispatch(); err != nil {
					return err
				}
			}
			pending = append(pending, prepared{record: &copyRecord, data: b, versions: versions})
			pendingBytes += preparedBytes
			if len(pending) == 32 || pendingBytes >= 4<<20 {
				return dispatch()
			}
			return nil
		})
		if err == nil {
			err = dispatch()
		}
		result <- err
	}()
	for j := range ordered {
		select {
		case <-j.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if j.err != nil {
			return j.err
		}
		for _, p := range j.records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := emit(p.record, p.data, p.versions); err != nil {
				return err
			}
		}
	}
	return <-result
}
