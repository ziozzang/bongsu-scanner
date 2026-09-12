package vulndb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSQLiteVersionsBlobBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, 127, 128, 129, 256, 259, 8192} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dir := t.TempDir()
			versions := make([]string, count)
			for i := range versions {
				versions[i] = fmt.Sprintf("%d.\x00'\"日本語", i%7)
			}
			r := &Record{ID: "OSV-batch", Source: SourceOSV, Affected: []Affected{{Ecosystem: "npm", Package: "batch", Versions: versions}, {Ecosystem: "npm", Package: "next", Versions: []string{"last"}}}}
			if err := buildSQLite(context.Background(), dir, map[string]*Record{r.ID: r}, &Meta{}); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if got := sqliteVersionsForTest(t, db, "batch"); !reflect.DeepEqual(got, versions) {
				t.Fatal("versions changed across former batch boundaries")
			}
			if got := sqliteVersionsForTest(t, db, "next"); !reflect.DeepEqual(got, []string{"last"}) {
				t.Fatalf("last versions = %q", got)
			}
		})
	}
}

func TestSQLiteCompressionPreservesOrderAndErrors(t *testing.T) {
	produce := func(emit Emit) error {
		for i := 0; i < 300; i++ {
			r := &Record{ID: fmt.Sprintf("OSV-%d", i), Details: strings.Repeat("variable compression work ", 1+i%11*100), Affected: []Affected{}}
			if err := emit(r); err != nil {
				return err
			}
		}
		return nil
	}
	count := 0
	err := visitCompressedSQLiteRecords(context.Background(), produce, func(r *Record, compressed []byte, _ [][]byte) error {
		if r.ID != fmt.Sprintf("OSV-%d", count) {
			t.Fatalf("out of order: %s at %d", r.ID, count)
		}
		var got Record
		if err := decodeSQLiteRecord(compressed, &got); err != nil {
			return err
		}
		wantJSON, _ := json.Marshal(r)
		gotJSON, _ := json.Marshal(&got)
		if string(wantJSON) != string(gotJSON) || got.Affected == nil {
			t.Fatal("compression changed record JSON")
		}
		count++
		return nil
	})
	if err != nil || count != 300 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	wantErr := errors.New("consumer stopped")
	if err := visitCompressedSQLiteRecords(context.Background(), produce, func(*Record, []byte, [][]byte) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("consumer error lost: %v", err)
	}
	if err := visitCompressedSQLiteRecords(context.Background(), func(emit Emit) error {
		if err := emit(&Record{ID: "OSV-valid"}); err != nil {
			return err
		}
		return wantErr
	}, func(*Record, []byte, [][]byte) error { return nil }); !errors.Is(err, wantErr) {
		t.Fatalf("producer error lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = visitCompressedSQLiteRecords(ctx, produce, func(*Record, []byte, [][]byte) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestSQLiteBatchRetainsForeignKeyChecks(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id));"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	batch, err := newSQLiteBatch(context.Background(), tx, "INSERT INTO child(id) VALUES", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer batch.close()
	if err := batch.add(7); err != nil {
		t.Fatal(err)
	}
	if err := batch.flush(); err == nil {
		t.Fatal("missing parent accepted")
	}
}
