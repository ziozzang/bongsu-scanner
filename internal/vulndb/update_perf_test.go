package vulndb

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

// These opt-in workload tests leave production profiling and network behavior
// untouched. Compile with go test -c, then use -test.cpuprofile/-test.memprofile.
func TestPerformanceUpdate(t *testing.T) {
	home := os.Getenv("BSCAN_PERF_HOME")
	if home == "" {
		t.Skip("set BSCAN_PERF_HOME to run the real feed workload")
	}
	opts := Options{Sources: []string{"osv", "alpine", "debian"}, Ecosystems: []string{"Alpine", "npm", "PyPI", "Go", "Debian", "crates.io"}, AlpineReleases: []string{"v3.20", "v3.21", "v3.22"}, Force: os.Getenv("BSCAN_PERF_FORCE") != "", Progress: func(s string) { fmt.Println(time.Now().Format(time.RFC3339), s) }}
	if replay := os.Getenv("BSCAN_PERF_REPLAY"); replay != "" {
		var meta Meta
		if err := readJSON(filepath.Join(replay, "meta.json"), &meta); err != nil {
			t.Fatal(err)
		}
		feeds := map[string]Feed{}
		for _, name := range opts.Sources {
			s, _ := LookupSource(name)
			fs, err := s.Feeds(&opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range fs {
				feeds[f.URL] = f
			}
		}
		previous := map[string]SourceMeta{}
		for _, m := range meta.Sources {
			previous[m.URL] = m
		}
		client := httpx.New(10 * time.Minute)
		client.HTTP.Transport = performanceTransport(func(r *http.Request) (*http.Response, error) {
			feed, ok := feeds[r.URL.String()]
			if !ok {
				return nil, fmt.Errorf("unexpected replay URL %s", r.URL)
			}
			m := previous[feed.URL]
			h := http.Header{}
			h.Set("ETag", m.ETag)
			h.Set("Last-Modified", m.LastMod)
			if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
				return &http.Response{StatusCode: 304, Status: "304 Not Modified", Header: h, Body: http.NoBody, Request: r}, nil
			}
			f, err := os.Open(filepath.Join(replay, "raw", feed.Source, feed.File))
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: h, Body: f, ContentLength: m.Bytes, Request: r}, nil
		})
		opts.Client = client
	}
	start := time.Now()
	m, err := Update(context.Background(), filepath.Join(home, "db"), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Update: %s, %d records", time.Since(start), m.Records)
}

type performanceTransport func(*http.Request) (*http.Response, error)

func (f performanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPerformanceLookups(t *testing.T) {
	dir, out := os.Getenv("BSCAN_PERF_DB"), os.Getenv("BSCAN_PERF_DUMP")
	if dir == "" || out == "" {
		t.Skip("set BSCAN_PERF_DB and BSCAN_PERF_DUMP")
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, q := range [][2]string{{"Debian", "curl"}, {"Debian", "linux"}, {"npm", "lodash"}, {"PyPI", "pillow"}, {"Alpine", "openssl"}} {
		rs, err := s.Lookup(q[0], q[1])
		if err != nil {
			t.Fatal(err)
		}
		// Ingestion timestamps intentionally advance between updates; all other
		// fields and the exact lookup ordering must remain byte identical.
		if os.Getenv("BSCAN_PERF_NORMALIZE_TIME") != "" {
			for i := range rs {
				rs[i].AddedAt = time.Time{}
				rs[i].LastSeenAt = time.Time{}
			}
		}
		if err := enc.Encode(rs); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s/%s: %d records", q[0], q[1], len(rs))
	}
}

func BenchmarkOSVZipSQLite50K(b *testing.B) {
	path := filepath.Join(b.TempDir(), "synthetic.zip")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := 0; i < 50_000; i++ {
		w, err := zw.Create(fmt.Sprintf("OSV-%06d.json", i))
		if err != nil {
			b.Fatal(err)
		}
		_, err = fmt.Fprintf(w, `{"id":"OSV-%06d","summary":"Synthetic advisory","details":"A reproducible vulnerability with package versions, references and severity.","aliases":["CVE-2025-%06d"],"severity":[{"type":"CVSS_V3","score":"7.5"}],"affected":[{"package":{"ecosystem":"npm","name":"package-%04d"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],"versions":["1.0.0","1.1.0","1.2.0","1.3.0","1.4.0","1.5.0","1.6.0","1.7.0"]}],"references":[{"type":"WEB","url":"https://example.com/advisory/%d"}]}`, i, i, i%1000, i)
		if err != nil {
			b.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		records := make(map[string]*Record, 50_000)
		_, err := parseOSVZip(context.Background(), path, SourceOSV, nil, func(r *Record) error { records[r.ID] = r; return nil }, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := buildSQLite(context.Background(), dir, records, &Meta{}); err != nil {
			b.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, SQLiteFileName)); err != nil {
			b.Fatal(err)
		}
	}
}

// Conversion preserves ingestion times, allowing unnormalized, byte-for-byte
// lookup comparisons against the original real catalog after builder changes.
func TestPerformanceConvert(t *testing.T) {
	src, dst := os.Getenv("BSCAN_PERF_DB"), os.Getenv("BSCAN_PERF_CONVERT")
	if src == "" || dst == "" {
		t.Skip("set BSCAN_PERF_DB and BSCAN_PERF_CONVERT")
	}
	if _, err := Convert(context.Background(), src, dst, Options{NoKeepRaw: true}); err != nil {
		t.Fatal(err)
	}
}
