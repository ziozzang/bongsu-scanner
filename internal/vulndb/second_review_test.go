package vulndb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestSecondReviewAutoDetectsModification(t *testing.T) {
	for _, mutation := range []string{"unchanged", "delete", "restore-mtime"} {
		t.Run(mutation, func(t *testing.T) {
			dir := readerCatalog(t)
			st, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if st.(*sqliteStore).snapshot != "" {
				t.Skip("fixture filesystem supports reflink")
			}
			path := filepath.Join(dir, SQLiteFileName)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "delete":
				db, err := sql.Open("sqlite", sqliteURI(path, false))
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec("DELETE FROM records")
				closeErr := db.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			case "restore-mtime":
				// Identical bytes and restored mtime/size still change ctime.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				changeCatalogCTime(t, path, before)
			}
			for _, lookup := range []func() ([]Record, error){
				func() ([]Record, error) { return st.Lookup("npm", "example") },
				func() ([]Record, error) { return st.Lookup("npm", "absent") },
				func() ([]Record, error) { return LookupID(st, "CVE-2025-1234") },
			} {
				records, err := lookup()
				if mutation == "unchanged" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "catalog modified during read") || records != nil {
					t.Fatalf("modified catalog returned records=%v err=%v", records, err)
				}
			}
			err = st.Close()
			if mutation == "unchanged" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "catalog modified during read") {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestSecondReviewAutoDetectsVerificationMutation(t *testing.T) {
	dir := readerCatalog(t)
	ctx := &replaceAfterVerification{Context: context.Background(), replace: func() {
		path := filepath.Join(dir, SQLiteFileName)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		changeCatalogCTime(t, path, before)
	}}
	st, err := OpenWithOptionsContext(ctx, dir, Options{Isolation: "auto"})
	if st != nil {
		st.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "catalog changed during verification") {
		t.Fatal(err)
	}
}

func TestSecondReviewConversionCacheVersion(t *testing.T) {
	for _, keepRaw := range []bool{true, false} {
		t.Run(fmt.Sprint("keep-raw=", keepRaw), func(t *testing.T) {
			raw := fixtureZip(t, map[string]string{"record.json": `{"id":"CVE-2026-1234","affected":[{"package":{"ecosystem":"Debian:unstable","name":"curl"},"versions":["1"],"severity":[{"type":"CVSS_V3","score":"high"}]}]}`})
			var conditional, unconditional atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
					conditional.Add(1)
					w.WriteHeader(http.StatusNotModified)
					return
				}
				unconditional.Add(1)
				w.Header().Set("ETag", `"fixture"`)
				w.Write(raw)
			}))
			defer srv.Close()
			client := httpx.New(time.Second)
			client.HTTP.Transport = srv.Client().Transport
			dir := filepath.Join(t.TempDir(), "db")
			opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"Debian"}, OSVBaseURL: srv.URL, Client: client, NoKeepRaw: !keepRaw}
			meta, err := Update(context.Background(), dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			// Recreate a verified generation containing output from an older converter.
			old := &Record{ID: "CVE-2026-1234", Source: SourceOSV, Affected: []Affected{{Ecosystem: "Debian:unstable", Package: "curl", Versions: []string{"1"}}}}
			meta.Sources[0].ConversionVersion = conversionCacheVersion - 1
			if err := writeRecords(filepath.Join(dir, "cache", SourceOSV, "Debian.jsonl.gz"), []*Record{old}); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, SQLiteFileName)); err != nil {
				t.Fatal(err)
			}
			meta.Ecosystems = nil
			if err := buildSQLite(context.Background(), dir, map[string]*Record{old.ID: old}, &meta); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
				t.Fatal(err)
			}
			if err := writeManifest(dir, Options{}); err != nil {
				t.Fatal(err)
			}
			meta, err = Update(context.Background(), dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			if meta.Sources[0].ConversionVersion != conversionCacheVersion {
				t.Fatal("cache version was not upgraded")
			}
			st, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			records, err := st.Lookup("Debian", "curl")
			if err != nil || len(records) != 1 {
				t.Fatal(records, err)
			}
			a := records[0].Affected[0]
			if a.Ecosystem != "Debian:sid" || len(a.Severity) != 1 {
				t.Fatalf("stale conversion reused: %+v", a)
			}
			if keepRaw && (conditional.Load() != 1 || unconditional.Load() != 1) {
				t.Fatal("retained raw was not reused")
			}
			if !keepRaw && (conditional.Load() != 0 || unconditional.Load() != 2) {
				t.Fatal("missing raw did not force unconditional fetch")
			}
		})
	}
}

func TestSecondReviewOSVVersionOverflowRetainsDatabase(t *testing.T) {
	testLimit(t, &osvMaxVersions, 10)
	testOSVVersionOverflowRetainsDatabase(t)
}

func TestHeavyOSVVersionOverflowRetainsDatabase(t *testing.T) {
	heavyTest(t)
	if osvMaxVersions != 5_000_000 {
		t.Fatal("production version limit changed", osvMaxVersions)
	}
	testOSVVersionOverflowRetainsDatabase(t)
}

func testOSVVersionOverflowRetainsDatabase(t *testing.T) {
	t.Helper()
	good := fixtureZip(t, map[string]string{"record.json": osvFixture("CVE-2026-1234", "npm", "example")})
	var feed atomic.Value
	feed.Store(good)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(feed.Load().([]byte)) }))
	defer srv.Close()
	client := httpx.New(30 * time.Second)
	client.HTTP.Transport = srv.Client().Transport
	opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"npm"}, OSVBaseURL: srv.URL, Client: client}
	dir := filepath.Join(t.TempDir(), "db")
	if _, err := Update(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	// Exceed the aggregate bound across two affected entries, each below it.
	versions := strings.Repeat(`"1",`, osvMaxVersions/2)
	affected := `{"package":{"ecosystem":"npm","name":"example"},"versions":[` + versions + `"2"]}`
	raw := `{"id":"CVE-2026-1234","affected":[` + affected + `,` + affected + `]}`
	feed.Store(fixtureZip(t, map[string]string{"record.json": raw}))
	meta, err := Update(context.Background(), dir, opts)
	if err == nil || !strings.Contains(err.Error(), "total versions") {
		t.Fatalf("overflow accepted: %v", err)
	}
	if len(meta.Sources) != 1 || !strings.Contains(meta.Sources[0].Error, "total versions") {
		t.Fatalf("feed error missing: %+v", meta)
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed feed replaced database", err)
	}
}

func TestSecondReviewDetailsStorageUTF8(t *testing.T) {
	dir := t.TempDir()
	details := strings.Repeat("한", 1000)
	rec := &Record{ID: "CVE-2026-1234", Details: details, Affected: []Affected{{Ecosystem: "npm", Package: "example"}}}
	meta := Meta{SchemaVersion: SchemaVersion}
	if err := buildSQLite(context.Background(), dir, map[string]*Record{rec.ID: rec}, &meta); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(filepath.Join(dir, SQLiteFileName), true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var preview string
	var truncated bool
	var encoded []byte
	if err := db.QueryRow("SELECT details,details_truncated,json FROM records").Scan(&preview, &truncated, &encoded); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(preview) || preview != "" || truncated != rec.DetailsTruncated {
		t.Fatalf("invalid preview: bytes=%d valid=%v truncated=%v", len(preview), utf8.ValidString(preview), truncated)
	}
	var decoded Record
	if err := decodeSQLiteRecord(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Details != details {
		t.Fatal("full details changed")
	}
}
