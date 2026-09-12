package vulndb

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAffectedIndexNameFromPURL(t *testing.T) {
	tests := []struct {
		name, ecosystem, purl, want string
	}{
		{name: "scoped npm", ecosystem: "npm", purl: "pkg:npm/%40scope/foo", want: "@scope/foo"},
		{name: "maven coordinate", ecosystem: "Maven", purl: "pkg:maven/org.apache/commons-lang3", want: "org.apache:commons-lang3"},
		{name: "debian release", ecosystem: "Debian:13", purl: "pkg:deb/debian/curl?distro=trixie", want: "curl"},
		{name: "alpine release", ecosystem: "Alpine:v3.20", purl: "pkg:apk/alpine/openssl?distro=3.20", want: "openssl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := affectedIndexName(Affected{Ecosystem: tt.ecosystem, PURL: tt.purl})
			if !ok || got != NormalizeName(tt.ecosystem, tt.want) {
				t.Fatalf("affectedIndexName = %q, %t; want %q", got, ok, NormalizeName(tt.ecosystem, tt.want))
			}
		})
	}
	if _, ok := affectedIndexName(Affected{Ecosystem: "npm", Package: "lodash", PURL: "pkg:pypi/lodash"}); ok {
		t.Fatal("mismatched known PURL ecosystem was indexable")
	}
}

func TestPURLOnlyEntriesPersistInLegacyAndSQLiteIndexes(t *testing.T) {
	record := &Record{ID: "CVE-2026-1234", Affected: []Affected{{
		Ecosystem: "npm", PURL: "pkg:npm/%40scope/foo",
		Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}}}},
	}}}

	legacyDir := filepath.Join(t.TempDir(), "legacy")
	legacyMeta := Meta{SchemaVersion: 1}
	if err := buildLegacyIndexes(legacyDir, map[string]*Record{record.ID: record}, &legacyMeta); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacyMeta.Ecosystems, []string{"npm"}) {
		t.Fatalf("legacy ecosystems = %v", legacyMeta.Ecosystems)
	}
	if err := writeJSON(filepath.Join(legacyDir, "meta.json"), legacyMeta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(legacyDir, Options{}); err != nil {
		t.Fatal(err)
	}
	legacy, err := Open(legacyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	got, err := legacy.Lookup("npm", "@scope/foo")
	if err != nil || len(got) != 1 || got[0].ID != record.ID {
		t.Fatalf("legacy PURL-only lookup = %+v, %v", got, err)
	}

	sqliteDir := filepath.Join(t.TempDir(), "sqlite")
	if err := os.MkdirAll(sqliteDir, 0755); err != nil {
		t.Fatal(err)
	}
	sqliteMeta := Meta{}
	if err := buildSQLite(context.Background(), sqliteDir, map[string]*Record{record.ID: record}, &sqliteMeta); err != nil {
		t.Fatal(err)
	}
	digest, err := hashFileContext(context.Background(), filepath.Join(sqliteDir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteSnapshot(sqliteDir, sqliteMeta, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err = store.Lookup("npm", "@scope/foo")
	if err != nil || len(got) != 1 || got[0].ID != record.ID {
		t.Fatalf("SQLite PURL-only lookup = %+v, %v", got, err)
	}
}

func TestConvertOSVNormalizesPURLOnlyPackagesAndRejectsMismatches(t *testing.T) {
	cases := []struct {
		name, ecosystem, purl, want string
	}{
		{name: "scoped npm", ecosystem: "npm", purl: "pkg:npm/%40scope/foo", want: "@scope/foo"},
		{name: "maven coordinate", ecosystem: "Maven", purl: "pkg:maven/org.apache/commons-lang3", want: "org.apache:commons-lang3"},
		{name: "debian release", ecosystem: "Debian:13", purl: "pkg:deb/debian/curl?distro=trixie", want: "curl"},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var v osvVuln
			v.ID = "GHSA-purl-" + string(rune('1'+i))
			v.Affected = []osvAffected{{}}
			v.Affected[0].Package.Ecosystem = tt.ecosystem
			v.Affected[0].Package.PURL = tt.purl
			r, ok := ConvertOSV(&v, SourceOSV)
			if !ok || len(r.Affected) != 1 || r.Affected[0].Package != tt.want {
				t.Fatalf("ConvertOSV = %+v, %t", r, ok)
			}
		})
	}
	var mismatch osvVuln
	mismatch.ID = "GHSA-purl-mismatch"
	mismatch.Affected = []osvAffected{{}}
	mismatch.Affected[0].Package.Ecosystem = "npm"
	mismatch.Affected[0].Package.Name = "lodash"
	mismatch.Affected[0].Package.PURL = "pkg:pypi/lodash"
	if r, ok := ConvertOSV(&mismatch, SourceOSV); ok || r != nil {
		t.Fatalf("mismatched PURL was accepted: %+v, %t", r, ok)
	}
}
