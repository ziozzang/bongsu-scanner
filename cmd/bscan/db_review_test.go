package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestReviewDBLookupReleaseMatchesSamePackage(t *testing.T) {
	records := []vulndb.Record{
		{ID: "wrong-package", Affected: []vulndb.Affected{{Ecosystem: "Debian:12", Package: "curl"}, {Ecosystem: "Debian:13", Package: "openssl"}}},
		{ID: "wrong-ecosystem", Affected: []vulndb.Affected{{Ecosystem: "Debian:12", Package: "curl"}, {Ecosystem: "Ubuntu:13", Package: "curl"}}},
		{ID: "right", Affected: []vulndb.Affected{{Ecosystem: "Debian:13", Package: "CuRL"}, {Ecosystem: "Debian:13", Package: "curl"}}},
		{ID: "purl", Affected: []vulndb.Affected{{Ecosystem: "Debian:13", PURL: "pkg:deb/debian/curl"}}},
		{ID: "wrong-purl", Affected: []vulndb.Affected{{Ecosystem: "Debian:13", Package: "curl", PURL: "pkg:npm/curl"}}},
	}
	got := filterDBLookupRelease(records, "Debian:13", " CURL ")
	if len(got) != 2 || got[0].ID != "right" || got[1].ID != "purl" {
		t.Fatalf("cross-package release match: %+v", got)
	}
	if base := filterDBLookupRelease(records, "Debian", "curl"); !reflect.DeepEqual(base, records) {
		t.Fatal("base lookup changed")
	}
}

func TestReviewDBStatusSanitizesEcosystemsAndSources(t *testing.T) {
	original := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Stdout = f
	defer func() { os.Stdout = original }()
	eco, source := "npm\x1b[2J\nFAKE", "osv\x1b[31m\nSOURCE"
	meta := vulndb.Meta{Ecosystems: []string{eco, "Debian:13"}, Sources: []vulndb.SourceMeta{{Name: source, ETag: "tag\x1b[2J"}}}
	if err = printDBMeta(meta); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(out), "\x1b\r") || strings.Contains(string(out), "\nFAKE") || strings.Contains(string(out), "\nSOURCE") {
		t.Fatalf("unsafe output: %q", out)
	}
	if !strings.Contains(string(out), httpx.Sanitize(eco)+", Debian:13") || !strings.Contains(string(out), httpx.Sanitize(source)+":") {
		t.Fatalf("missing sanitized metadata: %q", out)
	}
	if meta.Ecosystems[0] != eco {
		t.Fatal("mutated metadata")
	}
}

func TestReviewDBVerifySignatureDiscoveryIsBounded(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256.sig"), []byte("{}"+strings.Repeat(" ", 64<<10)), 0600); err != nil {
		t.Fatal(err)
	}
	err := cmdDB(context.Background(), []string{"verify", "--db", dir})
	if err == nil || !strings.Contains(err.Error(), "signature exceeds 64 KiB") {
		t.Fatal(err)
	}
}
