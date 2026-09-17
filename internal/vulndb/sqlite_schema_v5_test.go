package vulndb

import (
	"bytes"
	"compress/zlib"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sqliteVersionsForTest(t *testing.T, db *sql.DB, packageName string) []string {
	t.Helper()
	var blob []byte
	if err := db.QueryRow("SELECT versions_blob FROM affected WHERE package_name=?", packageName).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var versions []string
	if err := json.Unmarshal(b, &versions); err != nil {
		t.Fatal(err)
	}
	if versions == nil {
		t.Fatal("versions_blob must contain a JSON array, including empty lists")
	}
	return versions
}

func TestSQLiteSchemaV5CompactStorageAndLookup(t *testing.T) {
	dir := t.TempDir()
	r := &Record{ID: "MAL-v5", Summary: "Small summary", Details: strings.Repeat("full advisory 日本語 ", 300), Aliases: []string{"CVE-2026-54321"}, Affected: []Affected{{Ecosystem: "npm", Package: "lodash", Versions: []string{"1.0", "1.0", "2.0\x00\"日本語"}}, {Ecosystem: "npm", Package: "empty"}}}
	meta := Meta{}
	if err := buildSQLite(context.Background(), dir, map[string]*Record{r.ID: r}, &meta); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, tables int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != SQLiteSchemaVersion {
		t.Errorf("schema=%d constant=%d err=%v; want current schema", version, SQLiteSchemaVersion, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='affected_versions'").Scan(&tables); err != nil || tables != 0 {
		t.Errorf("per-version table remains: count=%d err=%v", tables, err)
	}
	var details, summary string
	var cut bool
	if err := db.QueryRow("SELECT summary,details,details_truncated FROM records").Scan(&summary, &details, &cut); err != nil || summary != r.Summary || details != "" || cut != r.DetailsTruncated {
		t.Errorf("duplicate details or altered summary/truncation: details bytes=%d cut=%v err=%v", len(details), cut, err)
	}
	if got := sqliteVersionsForTest(t, db, "lodash"); !reflect.DeepEqual(got, r.Affected[0].Versions) {
		t.Fatalf("versions changed: %q", got)
	}
	if got := sqliteVersionsForTest(t, db, "empty"); len(got) != 0 {
		t.Fatalf("empty versions: %q", got)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sortAffected(r.Affected)
	want, _ := json.Marshal([]Record{*r})
	for _, lookup := range []func() ([]Record, error){func() ([]Record, error) { return st.Lookup("npm", "lodash") }, func() ([]Record, error) { return LookupID(st, r.Aliases[0]) }} {
		got, err := lookup()
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(got)
		if err != nil || !bytes.Equal(b, want) {
			t.Fatalf("Lookup changed full record: err=%v", err)
		}
	}
}

func TestSQLiteSchemaV5RejectsV4BeforeColumnValidation(t *testing.T) {
	dir := readerCatalog(t)
	// Model the actual v4 layout, rather than just changing its version tag.
	alterReaderCatalog(t, dir, `DROP TABLE affected;
CREATE TABLE affected (
 id INTEGER PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id),
 ordinal INTEGER NOT NULL, ecosystem TEXT NOT NULL, base_ecosystem TEXT NOT NULL,
 release TEXT NOT NULL, package_name TEXT NOT NULL, normalized_name TEXT NOT NULL,
 purl TEXT, ecosystem_specific_json TEXT NOT NULL, database_specific_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS affected_versions(affected_id INTEGER, ordinal INTEGER, version TEXT);
PRAGMA user_version=4`)
	st, err := Open(dir)
	if st != nil {
		st.Close()
	}
	if !errors.Is(err, ErrUnsupportedCatalog) {
		t.Fatalf("v4 must request rebuild, got %v", err)
	}
}

func TestSQLiteDocumentedQueries(t *testing.T) {
	dir := t.TempDir()
	record := &Record{ID: "GHSA-docs", Summary: "SQL example", Aliases: []string{"CVE-2021-23337"}, Source: SourceOSV, Affected: []Affected{{Ecosystem: "npm", Package: "lodash", Versions: []string{"1.0.0"}, Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}}}
	if err := buildSQLite(context.Background(), dir, map[string]*Record{record.ID: record}, &Meta{}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "sqlite-queries.sql"))
	if err != nil {
		t.Fatal(err)
	}
	var statements strings.Builder
	for _, line := range strings.Split(string(doc), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			statements.WriteString(line + "\n")
		}
	}
	count := 0
	for _, query := range strings.Split(statements.String(), ";") {
		if strings.TrimSpace(query) == "" {
			continue
		}
		count++
		rows, err := db.Query(query)
		if err != nil {
			t.Fatalf("documented query %d: %v\n%s", count, err, query)
		}
		for rows.Next() {
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			t.Fatalf("documented query %d: %v", count, err)
		}
	}
	if count == 0 {
		t.Fatal("no documented queries executed")
	}
}
