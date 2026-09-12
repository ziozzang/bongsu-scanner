package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestLetterOnlyGHSAIdentifiers(t *testing.T) {
	for _, id := range []string{"GHSA-cpgg-pjqx-vqgp", "CVE-2025-1234", "PYSEC-2024-1"} {
		if !validID(id) {
			t.Errorf("valid advisory rejected: %s", id)
		}
	}
	for _, id := range []string{"", "GHSA-", "GHSA-../etc", "GHSA-x\nFORGED", "GHSA--x"} {
		if validID(id) {
			t.Errorf("invalid advisory accepted: %q", id)
		}
	}
	raw := fixtureZip(t, map[string]string{"valid.json": osvFixture("GHSA-cpgg-pjqx-vqgp", "npm", "example")})
	p := filepath.Join(t.TempDir(), "feed.zip")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var got []string
	n, err := parseOSVZip(context.Background(), p, SourceOSV, nil, func(r *Record) error { got = append(got, r.ID); return nil }, nil)
	if err != nil || n != 1 || len(got) != 1 || got[0] != "GHSA-cpgg-pjqx-vqgp" {
		t.Fatalf("n=%d got=%v err=%v", n, got, err)
	}
}

func TestCorruptOSVFeedPreservesInstalledDatabase(t *testing.T) {
	good := fixtureZip(t, map[string]string{"valid.json": osvFixture("GHSA-cpgg-pjqx-vqgp", "npm", "example")})
	var feed atomic.Value
	feed.Store(good)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(feed.Load().([]byte)) }))
	defer srv.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = srv.Client().Transport
	dir := filepath.Join(t.TempDir(), "db")
	opts := Options{Sources: []string{"osv"}, Ecosystems: []string{"npm"}, OSVBaseURL: srv.URL, Client: client, Force: true}
	if _, err := Update(context.Background(), dir, opts); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	// Store an uncompressed member, then alter valid JSON bytes without updating
	// its CRC. This detects implementations that stop decoding before EOF.
	var crc bytes.Buffer
	zw := zip.NewWriter(&crc)
	member, err := zw.CreateHeader(&zip.FileHeader{Name: "corrupt.json", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	member.Write([]byte(osvFixture("CVE-2025-1234", "npm", "example")))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	corruptCRC := bytes.Replace(crc.Bytes(), []byte("CVE-2025-1234"), []byte("CVE-2025-9999"), 1)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"malformed", fixtureZip(t, map[string]string{"bad.json": "{"})},
		{"trailing-json", fixtureZip(t, map[string]string{"bad.json": osvFixture("CVE-2025-1234", "npm", "example") + " {}"})},
		{"crc", corruptCRC},
		{"invalid-identifier", fixtureZip(t, map[string]string{"bad.json": `{"id":"","affected":[]}`})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			feed.Store(tc.data)
			if _, err := Update(context.Background(), dir, opts); err == nil {
				t.Fatal("corrupt feed update succeeded")
			}
			current, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(old, current) {
				t.Fatal("corrupt feed replaced installed database")
			}
			st, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			records, err := st.Lookup("npm", "example")
			st.Close()
			if err != nil || len(records) != 1 || !strings.HasPrefix(records[0].ID, "GHSA-") {
				t.Fatalf("records=%v err=%v", records, err)
			}
		})
	}
}

func TestFeedSelectionHonorsDownloadBounds(t *testing.T) {
	for _, limit := range []int64{1024, DefaultMaxFeedBytes, 2 * GHSAMaxBytes} {
		feeds, err := (ghsaSource{}).Feeds(&Options{MaxFeedBytes: limit})
		if err != nil || len(feeds) != 1 || feeds[0].MaxBytes != limit {
			t.Fatalf("limit=%d feeds=%v err=%v", limit, feeds, err)
		}
	}
	feeds, err := (ghsaSource{}).Feeds(&Options{})
	if err != nil || feeds[0].MaxBytes != GHSAMaxBytes {
		t.Fatalf("standalone GHSA default: %v %v", feeds, err)
	}
	feeds, err = (osvSource{}).Feeds(&Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, feed := range feeds {
		if feed.Key == "Ubuntu" || feed.Key == "Chainguard" {
			t.Fatalf("oversized default feed selected: %s", feed.Key)
		}
	}
	feeds, err = (osvSource{}).Feeds(&Options{Ecosystems: []string{"Ubuntu", "Chainguard"}, MaxFeedBytes: 2 << 30})
	if err != nil || len(feeds) != 2 {
		t.Fatalf("explicit large feeds: %v %v", feeds, err)
	}
	for _, feed := range feeds {
		if feed.MaxBytes != 2<<30 {
			t.Fatalf("explicit limit ignored: %d", feed.MaxBytes)
		}
	}
}
