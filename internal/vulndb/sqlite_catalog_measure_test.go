package vulndb

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in comparison of schema builds using exactly the same real Records.
// The source is read-only; the destination must not already exist.
func TestSQLiteRealCatalogRebuild(t *testing.T) {
	source, destination := os.Getenv("BSCAN_SQLITE_SOURCE"), os.Getenv("BSCAN_SQLITE_DEST")
	if source == "" || destination == "" {
		t.Skip("set BSCAN_SQLITE_SOURCE and BSCAN_SQLITE_DEST for real-catalog measurement")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(source, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var meta Meta
	if err := readJSON(filepath.Join(source, "meta.json"), &meta); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = buildSQLiteStream(context.Background(), destination, func(emit Emit) error {
		rows, err := db.Query("SELECT json FROM records ORDER BY id")
		if err != nil {
			return err
		}
		defer rows.Close()
		decoder := new(sqliteReadDecoder)
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return err
			}
			var r Record
			if err := decoder.decode(b, &r); err != nil {
				return err
			}
			if err := emit(&r); err != nil {
				return err
			}
		}
		return rows.Err()
	}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if err := writeJSON(filepath.Join(destination, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(destination, Options{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("schema=%d records=%d bytes=%d rebuild=%s", SQLiteSchemaVersion, meta.Records, info.Size(), elapsed)
}
