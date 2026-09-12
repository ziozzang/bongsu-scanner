package vulndb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func lookupIDRecords() []Record {
	return []Record{
		{ID: "CVE-2026-1000", Aliases: []string{"GHSA-shared", "CVE-2026-1000"}, Summary: "Complete advisory", Details: "Only Windows installations with feature X enabled are affected.", Source: "osv", Published: "2026-01-01T00:00:00Z", Modified: "2026-02-01T00:00:00Z", AddedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), LastSeenAt: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), Database: map[string]any{"severity": "HIGH"}, Affected: []Affected{{Ecosystem: "Debian:13", Package: "example", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "2.0-1"}}}}}, {Ecosystem: "npm", Package: "example", Versions: []string{"1.0.0"}}}},
		{ID: "GHSA-2026-second", Aliases: []string{"GHSA-shared"}, Details: "Second source", Source: "ghsa", Affected: []Affected{{Ecosystem: "npm", Package: "second"}}},
	}
}
func writeLookupIDFixture(t *testing.T, dir string, sqlite bool, records []Record) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Record{}
	for i := range records {
		byID[records[i].ID] = &records[i]
	}
	meta := Meta{SchemaVersion: 1, UpdatedAt: time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)}
	var err error
	if sqlite {
		err = buildIndexes(dir, byID, &meta)
	} else {
		err = buildLegacyIndexes(dir, byID, &meta)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err = writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
}
func TestLookupIDExactAliasAndFullRecord(t *testing.T) {
	for _, sqlite := range []bool{false, true} {
		name := "legacy"
		if sqlite {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			records := lookupIDRecords()
			dir := filepath.Join(t.TempDir(), "db")
			writeLookupIDFixture(t, dir, sqlite, records)
			store, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			got, err := LookupID(store, " CVE-2026-1000 ")
			if err != nil || len(got) != 1 {
				t.Fatalf("exact lookup: %+v %v", got, err)
			}
			if !reflect.DeepEqual(got[0], records[0]) {
				t.Fatalf("record fields lost\ngot=%+v\nwant=%+v", got[0], records[0])
			}
			got, err = LookupID(store, "GHSA-shared")
			if err != nil || len(got) != 2 || got[0].ID != "CVE-2026-1000" || got[1].ID != "GHSA-2026-second" {
				t.Fatalf("alias lookup: %+v %v", got, err)
			}
			for _, id := range []string{"missing", "CVE-2026-1000' OR 1=1 --", "%"} {
				got, err = LookupID(store, id)
				if err != nil || len(got) != 0 {
					t.Fatalf("nonmatch/injection query %q: %+v %v", id, got, err)
				}
			}
			if _, err = LookupID(store, ""); err == nil {
				t.Fatal("empty ID accepted")
			}
		})
	}
}
func TestLookupIDReturnsIndependentRecords(t *testing.T) {
	for _, sqlite := range []bool{false, true} {
		name := "legacy"
		if sqlite {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			records := lookupIDRecords()
			dir := filepath.Join(t.TempDir(), "db")
			writeLookupIDFixture(t, dir, sqlite, records)
			store, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// Populate the legacy package-lookup cache before querying by ID.
			if _, err = store.Lookup("npm", "example"); err != nil {
				t.Fatal(err)
			}
			got, err := LookupID(store, "CVE-2026-1000")
			if err != nil || len(got) != 1 {
				t.Fatalf("lookup %+v %v", got, err)
			}
			got[0].Aliases[0] = "changed"
			got[0].Database["severity"] = "LOW"
			got[0].Affected[0].Package = "changed"
			again, err := LookupID(store, "CVE-2026-1000")
			if err != nil || len(again) != 1 || !reflect.DeepEqual(again[0], records[0]) {
				t.Fatalf("caller mutation leaked %+v %v", again, err)
			}
		})
	}
}
func TestLookupIDUsesPinnedSnapshotAndClosedBehavior(t *testing.T) {
	for _, sqlite := range []bool{false, true} {
		name := "legacy"
		if sqlite {
			name = "sqlite"
		}
		t.Run(name, func(t *testing.T) {
			records := lookupIDRecords()
			dir := filepath.Join(t.TempDir(), "db")
			writeLookupIDFixture(t, dir, sqlite, records)
			old, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			previous := dir + ".old"
			if err = os.Rename(dir, previous); err != nil {
				t.Fatal(err)
			}
			replacement := lookupIDRecords()
			replacement[0].Details = "New generation"
			writeLookupIDFixture(t, dir, sqlite, replacement)
			if err = os.RemoveAll(previous); err != nil {
				t.Fatal(err)
			}
			got, err := LookupID(old, "GHSA-shared")
			if err != nil || len(got) != 2 || got[0].Details != records[0].Details {
				t.Fatalf("open reader changed generations %+v %v", got, err)
			}
			current, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			got, err = LookupID(current, "CVE-2026-1000")
			if err != nil || len(got) != 1 || got[0].Details != "New generation" {
				t.Fatalf("new reader missed replacement %+v %v", got, err)
			}
			if err = old.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = LookupID(old, "CVE-2026-1000"); err == nil {
				t.Fatal("lookup on closed store succeeded")
			}
		})
	}
}

type noIDStore struct{}

func (noIDStore) Lookup(string, string) ([]Record, error) { return nil, nil }
func (noIDStore) Ecosystems() ([]string, error)           { return nil, nil }
func (noIDStore) Meta() (Meta, error)                     { return Meta{}, nil }
func (noIDStore) Close() error                            { return nil }
func TestLookupIDUnsupportedStore(t *testing.T) {
	for _, store := range []Store{nil, noIDStore{}} {
		if _, err := LookupID(store, "CVE-2026-1000"); !errors.Is(err, ErrIDLookupUnsupported) {
			t.Fatalf("unsupported store: %v", err)
		}
	}
}
