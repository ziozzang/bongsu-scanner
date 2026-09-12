package vulndb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetailsColumnOmissionRoundTripAndSize(t *testing.T) {
	dir := t.TempDir()
	records := map[string]*Record{}
	for i, details := range []string{"", strings.Repeat("a", 2048), strings.Repeat("b", 2049), strings.Repeat("Long advisory detail. ", 8192)} {
		id := fmt.Sprintf("CVE-2026-%04d", 1000+i)
		records[id] = &Record{ID: id, Details: details, Affected: []Affected{{Ecosystem: "npm", Package: "example"}}}
	}
	meta := Meta{SchemaVersion: SchemaVersion}
	if err := buildSQLite(context.Background(), dir, records, &meta); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, SQLiteFileName)
	db, err := sql.Open("sqlite", sqliteURI(path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for id, rec := range records {
		var details string
		var truncated bool
		if err := db.QueryRow("SELECT details,details_truncated FROM records WHERE id=?", id).Scan(&details, &truncated); err != nil {
			t.Fatal(err)
		}
		if details != "" || truncated != rec.DetailsTruncated {
			t.Errorf("%s: details length=%d truncated=%v", id, len(details), truncated)
		}
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
	got, err := st.Lookup("npm", "example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(records) {
		t.Fatal("missing records")
	}
	for _, r := range got {
		if r.Details != records[r.ID].Details || r.DetailsTruncated != records[r.ID].DetailsTruncated {
			t.Error("API lost full details", r.ID)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for id, rec := range records {
		if _, err := db.Exec("UPDATE records SET details=?, details_truncated=0 WHERE id=?", rec.Details, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("catalog fixture: before=%d after=%d saved=%d bytes", before.Size(), after.Size(), before.Size()-after.Size())
	if after.Size() >= before.Size() {
		t.Error("catalog size did not decrease")
	}
}

func TestSQLiteRejectsPreviousDetailsSchema(t *testing.T) {
	dir := readerCatalog(t)
	alterReaderCatalog(t, dir, "PRAGMA user_version=3")
	st, err := Open(dir)
	if err == nil {
		st.Close()
	}
	if !errors.Is(err, ErrUnsupportedCatalog) {
		t.Fatalf("old catalog: %v", err)
	}
}
