package vulndb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMatchingVisitorRetainedValuesAndReset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	records := map[string]*Record{}
	for i, n := range []int{12, 1, 7} {
		r := &Record{ID: fmt.Sprintf("CVE-2026-%04d", i), Affected: make([]Affected, n)}
		for j := range r.Affected {
			r.Affected[j] = Affected{Ecosystem: "npm", Package: "fixture"}
			if i != 1 {
				r.Affected[j].Ranges = []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: fmt.Sprintf("%d.0.0", i+2)}}}}
				r.Affected[j].Database = map[string]any{"severity": "HIGH", "nested": map[string]any{"value": i}}
			}
		}
		if i != 1 {
			r.Aliases = []string{fmt.Sprintf("GHSA-%d", i)}
			r.Details = "full details"
			r.References = []Reference{{Type: "WEB", URL: "https://example.org"}}
		}
		records[r.ID] = r
	}
	meta := Meta{SchemaVersion: SchemaVersion}
	if err := buildIndexes(dir, records, &meta); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader := store.(*sqliteStore)
	want, err := reader.Lookup("npm", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	var got []Record
	if err := reader.LookupMatchingFunc(context.Background(), "npm", "fixture", func(r *Record) error {
		retained := *r
		retained.Affected = append([]Affected(nil), r.Affected...)
		got = append(got, retained)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Exercise the same pooled decoder again before checking retained values.
	if _, err := reader.Lookup("npm", "fixture"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("borrowed outer slice overwrote retained nested values or leaked fields from a previous record")
	}
	sentinel := errors.New("callback failure")
	if err := reader.LookupMatchingFunc(context.Background(), "npm", "fixture", func(*Record) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("lost callback error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := reader.LookupMatchingFunc(ctx, "npm", "fixture", func(*Record) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if _, err := reader.Lookup("npm", "fixture"); err != nil {
		t.Fatalf("query resources leaked: %v", err)
	}
}

func TestSQLiteDecoderPoolDropsOversizedBuffer(t *testing.T) {
	d := new(sqliteReadDecoder)
	d.input.Reset(make([]byte, 1<<20))
	d.output.Grow(2 << 20)
	releaseSQLiteReadDecoder(d)
	if d.input.Len() != 0 || d.output.Cap() != 0 {
		t.Fatal("pool retained an oversized advisory")
	}
}
