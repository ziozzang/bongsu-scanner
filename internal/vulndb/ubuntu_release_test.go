package vulndb

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestUbuntuEcosystemNormalization(t *testing.T) {
	for _, tc := range []struct{ ecosystem, base, release string }{
		{"Ubuntu", "Ubuntu", ""}, {"Ubuntu:24.04", "Ubuntu", "24.04"},
		{"Ubuntu:24.04:LTS", "Ubuntu", "24.04"}, {"Ubuntu:22.04:LTS", "Ubuntu", "22.04"},
		{"Ubuntu:Pro:18.04:LTS", "Ubuntu", "18.04"}, {"Ubuntu:Pro:24.04:LTS", "Ubuntu", "24.04"},
		{"Ubuntu:25.04", "Ubuntu", "25.04"}, {"Ubuntu:25.10", "Ubuntu", "25.10"},
		{"Ubuntu:26.04:LTS", "Ubuntu", "26.04"},
		// FIPS builds have a separate package stream, not generic Pro/ESM.
		{"Ubuntu:Pro:FIPS-updates:24.04:LTS", "Ubuntu", "Pro:FIPS-updates:24.04:LTS"},
		{"Ubuntu:Pro:FIPS:18.04:LTS", "Ubuntu", "Pro:FIPS:18.04:LTS"},
		{"Ubuntu:Pro:FIPS-preview:22.04:LTS", "Ubuntu", "Pro:FIPS-preview:22.04:LTS"},
		{"Ubuntu:future:LTS", "Ubuntu", "future:LTS"},
		{"Debian:13", "Debian", "13"}, {"Alpine:v3.20", "Alpine", "v3.20"},
		{"Rocky Linux:9", "Rocky Linux", "9"},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			if got := BaseEcosystem(tc.ecosystem); got != tc.base {
				t.Errorf("base=%q, want %q", got, tc.base)
			}
			if got := EcosystemRelease(tc.ecosystem); got != tc.release {
				t.Errorf("release=%q, want %q", got, tc.release)
			}
		})
	}
}

func TestUbuntuOSVConversionAndIndex(t *testing.T) {
	var input osvVuln
	err := json.Unmarshal([]byte(`{"id":"UBUNTU-CVE-2024-2511","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"}},{"package":{"ecosystem":"Ubuntu:Pro:24.04:LTS","name":"openssl"}}]}`), &input)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := ConvertOSV(&input, SourceOSV)
	if !ok || len(record.Affected) != 2 {
		t.Fatalf("conversion=%+v, ok=%t", record, ok)
	}
	dir := t.TempDir()
	if err := buildIndexes(dir, map[string]*Record{record.ID: record}, &Meta{SchemaVersion: SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM package_affected WHERE base_ecosystem='Ubuntu' AND name='openssl' AND release='24.04'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("normalized index rows=%d, error=%v", count, err)
	}
	for _, ecosystem := range []string{"Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"} {
		if err := db.QueryRow(`SELECT count(*) FROM affected WHERE ecosystem=? AND release='24.04'`, ecosystem).Scan(&count); err != nil || count != 1 {
			t.Fatalf("original ecosystem %s/normalized release rows=%d, error=%v", ecosystem, count, err)
		}
	}
}
