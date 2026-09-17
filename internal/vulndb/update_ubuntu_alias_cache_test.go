package vulndb

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestUbuntuAliasConversionCacheVersion3(t *testing.T) {
	for _, keepRaw := range []bool{true, false} {
		t.Run(fmt.Sprint("keep-raw=", keepRaw), func(t *testing.T) {
			raw := fixtureZip(t, map[string]string{"record.json": `{"id":"UBUNTU-CVE-2026-1234","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"curl"},"versions":["1"],"severity":[{"type":"CVSS_V3","score":"high"}]}]}`})
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
			opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"Ubuntu:24.04:LTS"}, OSVBaseURL: srv.URL, Client: client, NoKeepRaw: !keepRaw}
			meta, err := Update(context.Background(), dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			// Recreate a verified generation containing output from an older converter.
			old := &Record{ID: "UBUNTU-CVE-2026-1234", Source: SourceOSV, Affected: []Affected{{Ecosystem: "Ubuntu:24.04:LTS", Package: "curl", Versions: []string{"1"}}}}
			meta.Sources[0].ConversionVersion = 3 // Last converter version before Ubuntu CVE alias derivation.
			if err := writeRecords(filepath.Join(dir, "cache", SourceOSV, safeName("Ubuntu:24.04:LTS")+".jsonl.gz"), []*Record{old}); err != nil {
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
			records, err := st.Lookup("Ubuntu:24.04:LTS", "curl")
			if err != nil || len(records) != 1 {
				t.Fatal(records, err)
			}
			if !slices.Equal(records[0].Aliases, []string{"CVE-2026-1234"}) {
				t.Fatalf("stale conversion reused: aliases=%v", records[0].Aliases)
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
