package vulndb

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestRedHatMinorCatalogKeysAndLookup(t *testing.T) {
	cases := []struct{ ecosystem, release string }{
		{"Red Hat:enterprise_linux:8::baseos", "8"},
		{"Red Hat:enterprise_linux:9::appstream", "9"},
		{"Red Hat:enterprise_linux:10.0", "10.0"},
		{"Red Hat:enterprise_linux:10.2", "10.2"},
		{"Red Hat:enterprise_linux:11.1", "11.1"},
		{"Red Hat:rhel_eus:9.4::appstream", "rhel_eus:9.4"},
	}
	var records []Record
	for _, tc := range cases {
		records = append(records, Record{ID: "RHSA-" + tc.release, Affected: []Affected{{Ecosystem: tc.ecosystem, Package: "kernel"}}})
	}
	dir := t.TempDir()
	writeLookupIDFixture(t, dir, true, records)
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ecosystems, err := store.Ecosystems()
	if err != nil {
		t.Fatal(err)
	}
	coverage := map[string]bool{}
	for _, eco := range ecosystems {
		coverage[EcosystemRelease(eco)] = true
	}
	found, err := store.Lookup("Red Hat", "kernel")
	if err != nil || len(found) != len(cases) {
		t.Fatalf("lookup=%+v err=%v", found, err)
	}
	for _, tc := range cases {
		t.Run(tc.release, func(t *testing.T) {
			if got := EcosystemRelease(tc.ecosystem); got != tc.release {
				t.Errorf("release=%q, want %q", got, tc.release)
			}
			if !coverage[tc.release] {
				t.Errorf("missing coverage for %s: %v", tc.release, coverage)
			}
			var id string
			if err := db.QueryRow(`SELECT record_id FROM package_affected WHERE base_ecosystem='Red Hat' AND name='kernel' AND release=?`, tc.release).Scan(&id); err != nil || id != "RHSA-"+tc.release {
				t.Errorf("package index: id=%q err=%v", id, err)
			}
			var release string
			if err := db.QueryRow(`SELECT release FROM affected WHERE ecosystem=?`, tc.ecosystem).Scan(&release); err != nil || release != tc.release {
				t.Errorf("affected index: release=%q err=%v", release, err)
			}
		})
	}
}
