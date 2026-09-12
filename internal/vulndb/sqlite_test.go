package vulndb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func legacySQLiteFixture(t *testing.T, dir string, key ed25519.PrivateKey) Meta {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	r := &Record{ID: "CVE-2026-7777", Summary: "Environmental conditions", Details: strings.Repeat("details ", 400) + "Only Windows installations are affected.", Aliases: []string{"GHSA-cpgg-pjqx-vqgp"}, Affected: []Affected{{Ecosystem: "PyPI", Package: "Py_YAML"}, {Ecosystem: "Debian:13", Package: "curl"}, {Ecosystem: "Debian:12", Package: "curl"}}}
	meta := Meta{SchemaVersion: 1, UpdatedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), Sources: []SourceMeta{{Name: SourceOSV, URL: "https://example.invalid/feed.zip", ETag: "old-tag", Records: 1}}}
	if err := buildLegacyIndexes(dir, map[string]*Record{r.ID: r}, &meta); err != nil {
		t.Fatal(err)
	}
	if err := writeRecords(filepath.Join(dir, "cache", "osv", "PyPI.jsonl.gz"), []*Record{r}); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw", "osv", "sample.json")
	if err := os.MkdirAll(filepath.Dir(raw), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, []byte("original feed"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestSQLiteOfflineLegacyConversionAndIndexedLookup(t *testing.T) {
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "legacy")
	old := legacySQLiteFixture(t, src, priv)
	legacy, err := OpenVerified(src, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	want, err := legacy.Lookup("PyPI", "py.yaml")
	if err != nil || len(want) != 1 {
		t.Fatalf("legacy lookup: %+v %v", want, err)
	}
	dest := filepath.Join(t.TempDir(), "sqlite")
	meta, err := Convert(context.Background(), src, dest, Options{Offline: true, PublicKey: pub, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	if meta.SchemaVersion != 2 || !meta.UpdatedAt.Equal(old.UpdatedAt) || !reflect.DeepEqual(meta.Sources, old.Sources) || meta.Records != 1 {
		t.Fatalf("conversion metadata: %+v", meta)
	}
	header, err := os.ReadFile(filepath.Join(dest, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(header, []byte("SQLite format 3\x00")) {
		t.Fatal("not an actual SQLite catalog")
	}
	if _, err = os.Stat(filepath.Join(dest, "index")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("conversion retained legacy indexes", err)
	}
	current, err := OpenWithOptionsContext(context.Background(), dest, Options{PublicKey: pub, Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	got, err := current.Lookup("PyPI", "PY-YAML")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("SQLite lookup mismatch: %+v %v", got, err)
	}
	got, err = current.Lookup("Debian", "curl")
	if err != nil || len(got) != 1 {
		t.Fatalf("multiple releases duplicate advisory: %+v %v", got, err)
	}
	path, _ := filepath.Abs(filepath.Join(dest, SQLiteFileName))
	db, err := sql.Open("sqlite", sqliteURI(path, true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var details string
	var truncated bool
	if err = db.QueryRow("SELECT details,details_truncated FROM records WHERE id=?", "CVE-2026-7777").Scan(&details, &truncated); err != nil || details != "" || truncated != want[0].DetailsTruncated {
		t.Fatal("SQL details column must be empty", err)
	}
	var aliasID string
	if err = db.QueryRow("SELECT record_id FROM aliases WHERE alias=?", "GHSA-cpgg-pjqx-vqgp").Scan(&aliasID); err != nil || aliasID != "CVE-2026-7777" {
		t.Fatal("alias index missing", err)
	}
	rows, err := db.Query("EXPLAIN QUERY PLAN SELECT record_id FROM package_affected WHERE base_ecosystem=? AND name=?", "PyPI", "py-yaml")
	if err != nil {
		t.Fatal(err)
	}
	var plan string
	for rows.Next() {
		var id, parent, unused int
		var step string
		if err = rows.Scan(&id, &parent, &unused, &step); err != nil {
			t.Fatal(err)
		}
		plan += step
	}
	rows.Close()
	if !strings.Contains(plan, "INDEX") && !strings.Contains(plan, "PRIMARY KEY") {
		t.Fatalf("lookup is not indexed: %s", plan)
	}
	var metaJSON string
	if err = db.QueryRow("SELECT value FROM metadata WHERE key='meta'").Scan(&metaJSON); err != nil {
		t.Fatal(err)
	}
	var embedded Meta
	if err = json.Unmarshal([]byte(metaJSON), &embedded); err != nil || !reflect.DeepEqual(embedded, meta) {
		t.Fatal("SQL metadata mismatch", err)
	}
	// Conversion from SQLite is also offline and retains freshness and cache.
	again := filepath.Join(t.TempDir(), "converted")
	second, err := Convert(context.Background(), dest, again, Options{Offline: true, PublicKey: pub, NoKeepRaw: true})
	if err != nil || !second.UpdatedAt.Equal(old.UpdatedAt) {
		t.Fatal("SQLite conversion failed", err)
	}
	if _, err = os.Stat(filepath.Join(again, "raw")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("raw was retained")
	}
	if _, err = os.Stat(filepath.Join(again, "cache", "osv", "PyPI.jsonl.gz")); err != nil {
		t.Fatal("parsed cache was lost", err)
	}
	if err = Verify(again, pub); err == nil {
		t.Fatal("unsigned conversion incorrectly claimed signer")
	}
	if err = Verify(again, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteConversionInPlaceAndPinnedFailures(t *testing.T) {
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "db")
	old := legacySQLiteFixture(t, dir, priv)
	original, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Convert(context.Background(), dir, dir, Options{PublicKey: other}); err == nil {
		t.Fatal("wrong source signer accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if !bytes.Equal(original, after) {
		t.Fatal("failed conversion changed source")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Convert(ctx, dir, dir, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = Convert(context.Background(), dir, filepath.Join(dir, "nested"), Options{}); err == nil {
		t.Fatal("nested output accepted")
	}
	meta, err := Convert(context.Background(), dir, dir, Options{PublicKey: pub, PrivateKey: priv})
	if err != nil || !meta.UpdatedAt.Equal(old.UpdatedAt) {
		t.Fatal("in-place conversion failed", err)
	}
	st, err := OpenVerified(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok := st.(*sqliteStore); !ok {
		t.Fatalf("not SQLite: %T", st)
	}
	prev, err := OpenVerified(dir+".prev", pub)
	if err != nil {
		t.Fatal(err)
	}
	defer prev.Close()
	m, _ := prev.Meta()
	if m.SchemaVersion != 1 {
		t.Fatal("previous legacy generation lost")
	}
}

type cancelWhenStagedFileWritten struct {
	context.Context
	destination string
	rel         string
}

func (c *cancelWhenStagedFileWritten) Err() error {
	stages, _ := filepath.Glob(filepath.Join(filepath.Dir(c.destination), filepath.Base(c.destination)+".tmp-*"))
	for _, stage := range stages {
		if info, err := os.Stat(filepath.Join(stage, c.rel)); err == nil && info.Size() > 0 {
			return context.Canceled
		}
	}
	return nil
}

func TestConvertCancellationDuringRetainedFileCopy(t *testing.T) {
	source := readerCatalog(t)
	raw := filepath.Join(source, "raw", "osv", "large.zip")
	if err := os.MkdirAll(filepath.Dir(raw), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, bytes.Repeat([]byte("retained raw payload"), 1<<18), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "manifest.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(source, Options{}); err != nil {
		t.Fatal(err)
	}
	destination := readerCatalog(t)
	before, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelWhenStagedFileWritten{Context: context.Background(), destination: destination, rel: filepath.Join("raw", "osv", "large.zip")}
	if _, err = Convert(ctx, source, destination, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("conversion cancellation returned %v", err)
	}
	after, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("canceled conversion replaced destination")
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(destination), filepath.Base(destination)+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("canceled conversion leaked staging directories: %v", stages)
	}
}

func TestSQLiteQueryableRulesProvenanceAndTimestamps(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 10, 1, 2, 3, 0, time.UTC)
	rec := &Record{ID: "CVE-2026-8888", Source: SourceOSV, Provenance: []RecordSource{{Name: SourceOSV, URL: "https://example.invalid/npm/all.zip"}}, Summary: "A defect", Details: "Only a configured daemon is affected", DetailsTruncated: true, Published: "2025-01-02T03:04:05Z", Modified: "2025-02-02T03:04:05Z", AddedAt: at.Add(-time.Hour), LastSeenAt: at, References: []Reference{{Type: "ADVISORY", URL: "https://example.invalid/advisory/8888"}}, Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, Affected: []Affected{{Ecosystem: "Debian:13", Package: "Curl", PURL: "pkg:deb/debian/curl", Specific: map[string]any{"urgency": "high"}, Database: map[string]any{"source": "upstream"}, Versions: []string{"1.0", "1.1"}, Ranges: []Range{{Type: "ECOSYSTEM", Repo: "https://example.invalid/repo", Events: []Event{{Introduced: "0"}, {Fixed: "1.2"}, {Introduced: "2.0"}, {LastAffected: "2.2"}, {Introduced: "3.0"}, {Limit: "4.0"}}}}}}}
	meta := Meta{UpdatedAt: at, Sources: []SourceMeta{{Name: SourceOSV, URL: "https://example.invalid/npm/all.zip", FetchedAt: at, Records: 1}, {Name: SourceOSV, URL: "https://example.invalid/PyPI/all.zip", FetchedAt: at, Records: 100}}}
	if err := buildSQLite(context.Background(), dir, map[string]*Record{rec.ID: rec}, &meta); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var source, published, modified, added, seen, details string
	var withdrawn sql.NullString
	var cut bool
	if err = db.QueryRow("SELECT source,published_at,modified_at,withdrawn_at,added_at,last_seen_at,details,details_truncated FROM records WHERE id=?", rec.ID).Scan(&source, &published, &modified, &withdrawn, &added, &seen, &details, &cut); err != nil {
		t.Fatal(err)
	}
	if source != rec.Source || published != rec.Published || modified != rec.Modified || withdrawn.Valid || added != rec.AddedAt.Format(time.RFC3339Nano) || seen != at.Format(time.RFC3339Nano) || details != "" || !cut {
		t.Fatal("queryable record columns differ from advisory")
	}
	rows, err := db.Query(`SELECT e.introduced,e.fixed,e.last_affected,e.limit_version FROM affected a JOIN affected_ranges g ON g.affected_id=a.id JOIN range_events e ON e.range_id=g.id WHERE a.record_id=? AND a.base_ecosystem='Debian' AND a.normalized_name='curl' ORDER BY a.ordinal,g.ordinal,e.ordinal`, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []Event
	for rows.Next() {
		var i, f, l, v sql.NullString
		if err = rows.Scan(&i, &f, &l, &v); err != nil {
			t.Fatal(err)
		}
		got = append(got, Event{Introduced: i.String, Fixed: f.String, LastAffected: l.String, Limit: v.String})
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if !reflect.DeepEqual(got, rec.Affected[0].Ranges[0].Events) {
		t.Fatalf("SQL version rules differ: %+v", got)
	}
	if versions := sqliteVersionsForTest(t, db, "Curl"); !reflect.DeepEqual(versions, rec.Affected[0].Versions) {
		t.Fatal("explicit versions lost")
	}
	var repo, eco, release, rawName, purl, specific, database string
	if err = db.QueryRow("SELECT g.repo,a.ecosystem,a.release,a.package_name,a.purl,a.ecosystem_specific_json,a.database_specific_json FROM affected a JOIN affected_ranges g ON a.id=g.affected_id").Scan(&repo, &eco, &release, &rawName, &purl, &specific, &database); err != nil {
		t.Fatal(err)
	}
	if repo != rec.Affected[0].Ranges[0].Repo || eco != "Debian:13" || release != "13" || rawName != "Curl" || purl != rec.Affected[0].PURL || !strings.Contains(specific, "urgency") || !strings.Contains(database, "upstream") {
		t.Fatal("affected SQL details differ")
	}
	var url string
	var count int
	if err = db.QueryRow("SELECT count(*),min(s.url) FROM record_sources r JOIN sources s ON r.source=s.name AND r.url=s.url WHERE r.record_id=?", rec.ID).Scan(&count, &url); err != nil || count != 1 || url != rec.Provenance[0].URL {
		t.Fatalf("ambiguous feed provenance %d %s %v", count, url, err)
	}
	if err = db.QueryRow("SELECT url FROM advisory_references WHERE record_id=?", rec.ID).Scan(&url); err != nil || url != rec.References[0].URL {
		t.Fatal("advisory URL lost", err)
	}
	var score string
	if err = db.QueryRow("SELECT score FROM severities WHERE record_id=?", rec.ID).Scan(&score); err != nil || score != rec.Severity[0].Score {
		t.Fatal("severity lost", err)
	}
}
