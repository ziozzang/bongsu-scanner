package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/sign"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func cliTestDB(t *testing.T) string {
	t.Helper()
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	member, err := zw.Create("GHSA-2345-6789-abcd.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = member.Write([]byte(`{"id":"GHSA-2345-6789-abcd","aliases":["CVE-2026-12345"],"summary":"Fixture advisory","details":"This vulnerability occurs only on Windows. Linux installations are not affected.","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"npm","name":"fixture"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(zipped.Bytes())
	}))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	_, err = vulndb.Update(context.Background(), dir, vulndb.Options{Sources: []string{"osv"}, Ecosystems: []string{"npm"}, OSVBaseURL: server.URL, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDBCommandOfflineAndArguments(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	err := run(context.Background(), []string{"db", "update"})
	if err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline update: %v", err)
	}
	for _, args := range [][]string{{"db"}, {"db", "bogus"}, {"db", "lookup"}, {"db", "export"}, {"db", "import"}, {"db", "status", "extra"}} {
		if err := run(context.Background(), args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestDBLookupFiltersRequestedRelease(t *testing.T) {
	records := []vulndb.Record{
		{ID: "CVE-2026-1000", Affected: []vulndb.Affected{{Ecosystem: "Alpine:v3.19", Package: "openssl"}}},
		{ID: "CVE-2026-2000", Affected: []vulndb.Affected{{Ecosystem: "Alpine:v3.20", Package: "openssl"}}},
		{ID: "CVE-2026-3000", Affected: []vulndb.Affected{{Ecosystem: "Alpine:v3.19", Package: "openssl"}, {Ecosystem: "Alpine:v3.20", Package: "openssl"}}},
	}
	got := filterDBLookupRelease(records, "Alpine:v3.20", "openssl")
	if len(got) != 2 || got[0].ID != "CVE-2026-2000" || got[1].ID != "CVE-2026-3000" {
		t.Fatalf("release lookup returned %+v", got)
	}
	if got = filterDBLookupRelease(records, "Alpine", "openssl"); len(got) != len(records) {
		t.Fatalf("base ecosystem lookup filtered %d records", len(got))
	}
}

func TestDBCommandsExportImportAndVerify(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_OFFLINE", "1")
	db := cliTestDB(t)
	archive := filepath.Join(t.TempDir(), "database.tar.gz")
	imported := filepath.Join(t.TempDir(), "imported")
	converted := filepath.Join(t.TempDir(), "converted")
	for _, args := range [][]string{
		{"db", "status", "--db", db},
		{"db", "verify", "--db", db},
		{"db", "lookup", "--db", db + "/", "npm", "fixture"},
		{"db", "show", "--db", db, "CVE-2026-12345"},
		{"db", "export", "--db", db, archive},
		{"db", "import", "--db", imported, archive},
		{"db", "verify", "--db", imported},
		{"db", "convert", "--db", imported, converted},
		{"db", "lookup", "--db", converted, "npm", "fixture"},
	} {
		if err := run(context.Background(), args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := sign.FileDigest(filepath.Join(imported, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	record, err := sign.Create(digest, "manifest.sha256", "fixture", priv, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.WriteRecord(filepath.Join(imported, "manifest.sha256.sig"), record); err != nil {
		t.Fatal(err)
	}
	pem, err := sign.MarshalPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(keyPath, pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDB(context.Background(), []string{"verify", "--db", imported}); err == nil {
		t.Fatal("accepted untrusted signature")
	}
	if err := cmdDB(context.Background(), []string{"verify", "--db", imported, "--pubkey", keyPath}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.PublicKey = keyPath
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cmdDB(context.Background(), []string{"verify", "--db", imported}); err != nil {
		t.Fatal(err)
	}
}
