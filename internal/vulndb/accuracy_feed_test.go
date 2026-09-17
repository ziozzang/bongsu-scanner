package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestAccuracyExpandedLimitNamesFlag(t *testing.T) {
	body := osvFixture("CVE-2026-1234", "Ubuntu:24.04", "expat")
	p := filepath.Join(t.TempDir(), "feed.zip")
	if err := os.WriteFile(p, fixtureZip(t, map[string]string{"a.json": body, "b.json": body}), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := parseOSVZipBounded(context.Background(), p, SourceOSV, nil, func(*Record) error { t.Fatal("emitted over-limit feed"); return nil }, nil, 2, uint64(2*len(body)-1))
	if n != 0 || err == nil || !strings.Contains(err.Error(), "--max-feed-uncompressed") {
		t.Fatalf("count=%d error=%v", n, err)
	}
}

func TestAccuracyDebianUrgency(t *testing.T) {
	for _, tc := range []struct{ eco, database, want string }{
		{"Debian:bookworm", "", "unimportant"},
		{"Debian", `,"database_specific":{"other":true}`, "unimportant"},
		{"Debian:13", `,"database_specific":{"urgency":"high"}`, "high"},
		{"Ubuntu:24.04", "", ""},
	} {
		t.Run(tc.eco, func(t *testing.T) {
			var v osvVuln
			if err := json.Unmarshal([]byte(`{"id":"CVE-2019-1010022","affected":[{"package":{"ecosystem":"`+tc.eco+`","name":"glibc"},"ecosystem_specific":{"urgency":"unimportant"}`+tc.database+`}]}`), &v); err != nil {
				t.Fatal(err)
			}
			r, ok := ConvertOSV(&v, SourceOSV)
			if !ok {
				t.Fatal("record dropped")
			}
			got, _ := r.Affected[0].Database["urgency"].(string)
			if got != tc.want {
				t.Fatalf("urgency=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestAccuracyDebianMarkers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "debian.json")
	fixture := `{"sqlite3":{"CVE-2026-39113":{"releases":{"bookworm":{"status":"resolved","fixed_version":"0"},"trixie":{"status":"resolved"}}}},"pam":{"CVE-2025-8941":{"releases":{"bookworm":{"status":"undetermined"},"trixie":{"status":"undetermined","fixed_version":"1.0"}}}}}`
	if err := os.WriteFile(p, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	err := parseDebianTracker(context.Background(), p, func(r *Record) error {
		count++
		want := "not-affected"
		if r.ID == "CVE-2025-8941" {
			want = "undetermined"
		}
		if len(r.Affected) != 2 {
			t.Fatalf("affected=%+v", r.Affected)
		}
		for _, a := range r.Affected {
			if a.Database["debian_status"] != want || len(a.Ranges) != 0 || len(a.Versions) != 0 {
				t.Fatalf("marker=%+v", a)
			}
		}
		return nil
	})
	if err != nil || count != 2 {
		t.Fatalf("records=%d error=%v", count, err)
	}
}

func TestAccuracyIngestionDebianMarkerPrecedence(t *testing.T) {
	for _, status := range []string{"not-affected", "undetermined"} {
		for _, reverse := range []bool{false, true} {
			s, err := newIngestionSpool(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			records := []*Record{
				{ID: "CVE-2026-39113", Source: SourceOSV, Affected: []Affected{
					{Ecosystem: "Debian:13", Package: "sqlite3", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}, Database: map[string]any{"debian_status": "open", "osv": true}},
					{Ecosystem: "Debian:12", Package: "sqlite3", Versions: []string{"1"}},
					{Ecosystem: "Debian:13", Package: "other", Versions: []string{"1"}},
				}},
				{ID: "CVE-2026-39113", Source: SourceDebian, Affected: []Affected{{Ecosystem: "Debian:13", Package: "sqlite3", Database: map[string]any{"debian_status": status}}}},
			}
			if reverse {
				records[0], records[1] = records[1], records[0]
			}
			for _, r := range records {
				data, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.append(r.ID, append(data, '\n')); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.close(); err != nil {
				t.Fatal(err)
			}
			count := 0
			err = s.visit(context.Background(), nil, time.Now(), func(r *Record) error {
				count++
				if len(r.Affected) != 4 {
					t.Fatalf("entries lost: %+v", r.Affected)
				}
				for _, a := range r.Affected {
					if a.Ecosystem == "Debian:13" && a.Package == "sqlite3" {
						if a.Database["debian_status"] != status {
							t.Fatalf("reverse=%v: lost %s marker: %+v", reverse, status, a)
						}
						if len(a.Ranges) > 0 && a.Database["osv"] != true {
							t.Fatal("lost OSV metadata")
						}
					} else if a.Database["debian_status"] != nil {
						t.Fatalf("marker escaped package/release: %+v", a)
					}
				}
				return nil
			})
			if err != nil || count != 1 {
				t.Fatalf("records=%d error=%v", count, err)
			}
		}
	}
}

func TestAccuracyFeedUncompressedOptions(t *testing.T) {
	body := osvFixture("CVE-2026-1234", "Debian:13", "sqlite3")
	p := filepath.Join(t.TempDir(), "feed.zip")
	if err := os.WriteFile(p, fixtureZip(t, map[string]string{"advisories/github-reviewed/a.json": body, "advisories/github-reviewed/b.json": body}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []Source{osvSource{}, ghsaSource{}} {
		for _, limit := range []int64{-1, 0, int64(2*len(body) - 1), int64(2 * len(body))} {
			feeds, err := source.Feeds(&Options{Ecosystems: []string{"Debian"}, MaxFeedUncompressedBytes: limit})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			err = feeds[0].Parse(context.Background(), p, 0, func(*Record) error { count++; return nil }, nil)
			if limit == int64(2*len(body)-1) {
				if err == nil || !strings.Contains(err.Error(), "--max-feed-uncompressed") || count != 0 {
					t.Fatalf("%s limit=%d count=%d error=%v", source.Name(), limit, count, err)
				}
			} else if err != nil || count != 2 {
				t.Fatalf("%s limit=%d count=%d error=%v", source.Name(), limit, count, err)
			}
		}
	}
	// An ignored member declares 5 GiB without allocating or expanding it.
	// This crosses the old 4 GiB cap and must fit under the new default.
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	if _, err := zw.CreateRaw(&zip.FileHeader{Name: "ignored.txt", Method: zip.Store, UncompressedSize64: 5 << 30}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []Source{osvSource{}, ghsaSource{}} {
		feeds, err := source.Feeds(&Options{Ecosystems: []string{"Ubuntu"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := feeds[0].Parse(context.Background(), p, 0, func(*Record) error { t.Fatal("ignored member emitted"); return nil }, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccuracyUpdateReprocessesDebianConversionV1(t *testing.T) {
	archive := fixtureZip(t, map[string]string{"record.json": `{"id":"CVE-2026-39113","affected":[{"package":{"ecosystem":"Debian:13","name":"sqlite3"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"unimportant"}}]}`})
	tracker := []byte(`{"sqlite3":{"CVE-2026-39113":{"releases":{"trixie":{"status":"resolved","fixed_version":"0"}}}}}`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"fixture"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"fixture"`)
		if r.URL.Path == "/tracker" {
			_, _ = w.Write(tracker)
		} else {
			_, _ = w.Write(archive)
		}
	}))
	defer srv.Close()
	client := httpx.New(5 * time.Second)
	client.HTTP.Transport = srv.Client().Transport
	for _, sources := range [][]string{{SourceOSV, SourceDebian}, {SourceDebian, SourceOSV}} {
		for _, noRaw := range []bool{false, true} {
			dir := filepath.Join(t.TempDir(), "db")
			opts := Options{Sources: sources, Ecosystems: []string{"Debian"}, OSVBaseURL: srv.URL, DebianURL: srv.URL + "/tracker", Client: client, NoKeepRaw: noRaw}
			meta, err := Update(context.Background(), dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate version 1 caches: Debian markers and OSV urgency were lost.
			old := &Record{ID: "CVE-2026-39113", Source: SourceOSV, Affected: []Affected{{Ecosystem: "Debian:13", Package: "sqlite3", Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}}}}
			if err := writeRecords(filepath.Join(dir, "cache", SourceOSV, "Debian.jsonl.gz"), []*Record{old}); err != nil {
				t.Fatal(err)
			}
			if err := writeRecords(filepath.Join(dir, "cache", SourceDebian, "debian.jsonl.gz"), nil); err != nil {
				t.Fatal(err)
			}
			for i := range meta.Sources {
				meta.Sources[i].ConversionVersion = 1
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
			if _, err := Update(context.Background(), dir, opts); err != nil {
				t.Fatal(err)
			}
			st, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			records, err := st.Lookup("Debian", "sqlite3")
			if closeErr := st.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil || len(records) != 1 || len(records[0].Affected) != 2 {
				t.Fatalf("sources=%v noRaw=%v records=%+v error=%v", sources, noRaw, records, err)
			}
			for _, a := range records[0].Affected {
				if a.Database["debian_status"] != "not-affected" {
					t.Fatalf("marker lost: %+v", a)
				}
				if len(a.Ranges) > 0 && a.Database["urgency"] != "unimportant" {
					t.Fatalf("urgency lost: %+v", a)
				}
			}
		}
	}
}

func TestAccuracyFeedCacheBudget(t *testing.T) {
	for _, source := range []string{SourceOSV, SourceGHSA, SourceRedHatVEX} {
		if got := feedCacheLimit(source, Options{}); got != DefaultMaxFeedUncompressedBytes {
			t.Fatalf("%s default cache budget=%d", source, got)
		}
		if got := feedCacheLimit(source, Options{MaxFeedUncompressedBytes: 64 << 30}); got != 64<<30 {
			t.Fatalf("%s configured cache budget=%d", source, got)
		}
		if got := feedCacheLimit(source, Options{MaxFeedUncompressedBytes: 1}); got != 1<<30 {
			t.Fatalf("%s lost legacy minimum=%d", source, got)
		}
	}
	if got := feedCacheLimit(SourceDebian, Options{}); got != 1<<30 {
		t.Fatalf("unrelated cache budget changed: %d", got)
	}
	r := &Record{ID: "CVE-2026-1234", Source: SourceOSV, Affected: []Affected{{Ecosystem: "Ubuntu:24.04", Package: "expat"}}}
	feed := Feed{Source: SourceOSV, Parse: func(_ context.Context, _ string, _ int64, emit Emit, _ func(string)) error { return emit(r) }}
	// Match the provenance inserted by the writer before measuring a small cache.
	addProvenance(r, RecordSource{Name: SourceOSV})
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(data) + 1)
	p := filepath.Join(t.TempDir(), "cache.gz")
	if n, err := streamFeedCache(context.Background(), feed, "", p, 0, nil, size, 64<<20); err != nil || n != 1 {
		t.Fatalf("count=%d error=%v", n, err)
	}
	count := 0
	if err := readFeedCache(p, size, func(*Record) error { count++; return nil }); err != nil || count != 1 {
		t.Fatalf("count=%d error=%v", count, err)
	}
	if err := readFeedCache(p, size-1, func(*Record) error { return nil }); err == nil {
		t.Fatal("cache read exceeded configured budget")
	}
}
