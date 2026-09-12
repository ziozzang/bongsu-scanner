package vulndb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readerCatalog(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	meta := Meta{SchemaVersion: SchemaVersion}
	rec := &Record{ID: "CVE-2025-1234", Affected: []Affected{{Ecosystem: "npm", Package: "example"}}}
	if err := buildIndexes(dir, map[string]*Record{rec.ID: rec}, &meta); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func alterReaderCatalog(t *testing.T, dir, query string) {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(path, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(query); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// A portable imported archive can legitimately have self-consistent hashes
	// while still carrying an unsupported or malicious SQLite schema.
	if err := os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteReaderRejectsExecutableSchemas(t *testing.T) {
	for _, tc := range []struct{ name, query, want string }{
		{"metadata-view", `DROP TABLE metadata; CREATE VIEW metadata AS SELECT 'meta' AS key, randomblob(1000000000) AS value`, "ordinary table"},
		{"advisory-view", `ALTER TABLE records RENAME TO original_records; CREATE VIEW records AS SELECT id,randomblob(1000000000) AS json FROM original_records`, "ordinary table"},
		{"generated-metadata", `DROP TABLE metadata; CREATE TABLE metadata(key TEXT,value TEXT GENERATED ALWAYS AS (hex(key)) VIRTUAL)`, "generated or hidden"},
		{"missing-columns", `DROP TABLE metadata; CREATE TABLE metadata(key TEXT,other TEXT)`, "unexpected columns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := readerCatalog(t)
			alterReaderCatalog(t, dir, tc.query)
			if err := Verify(dir, nil); err != nil {
				t.Fatalf("fixture checksums invalid: %v", err)
			}
			st, err := Open(dir)
			if err == nil {
				st.Close()
				t.Fatal("executable schema accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong rejection: %v", err)
			}
			snapshots, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), ".bscan-db-reader-*"))
			if len(snapshots) != 0 {
				t.Fatalf("failed open leaked snapshots: %v", snapshots)
			}
		})
	}
}

func TestSQLiteConnectionRejectsOversizedImportedRows(t *testing.T) {
	dir := readerCatalog(t)
	alterReaderCatalog(t, dir, `UPDATE records SET json=zeroblob(67108865)`)
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Lookup("npm", "example")
	if err == nil {
		t.Fatal("oversized imported row returned")
	}
	// SQLITE_TOOBIG is raised by SQLite before database/sql scans into a Go
	// string, rather than by the post-scan advisory JSON length fallback.
	if !strings.Contains(strings.ToLower(err.Error()), "too big") && !strings.Contains(err.Error(), "SQLITE_TOOBIG") {
		t.Fatalf("missing engine-side size rejection: %v", err)
	}
}

func TestSQLitePinnedConnectionPolicies(t *testing.T) {
	dir := readerCatalog(t)
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.(*sqliteStore)
	for pragma, want := range map[string]int{"query_only": 1, "trusted_schema": 0} {
		var got int
		if err := st.conn.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&got); err != nil || got != want {
			t.Fatalf("%s=%d err=%v", pragma, got, err)
		}
	}
	if _, err := st.conn.ExecContext(context.Background(), "DELETE FROM records"); err == nil {
		t.Fatal("reader permitted mutation")
	}
	snapshot := st.snapshot
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot not removed: %v", err)
	}
	if _, err := st.Lookup("npm", "example"); err == nil {
		t.Fatal("closed store still queries")
	}
}

func TestSQLiteSnapshotSurvivesInPlaceSourceMutation(t *testing.T) {
	dir := readerCatalog(t)
	store, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.WriteFile(filepath.Join(dir, SQLiteFileName), []byte("corrupt source after verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := store.Lookup("npm", "example")
	if err != nil || len(records) != 1 || records[0].ID != "CVE-2025-1234" {
		t.Fatalf("private snapshot changed with source: %+v %v", records, err)
	}
}
