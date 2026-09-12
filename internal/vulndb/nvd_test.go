package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

const tinyNVDFeed = `{"vulnerabilities":[
 {"cve":{"id":"CVE-2025-1234","published":"2025-01-02T03:04:05.123","lastModified":"2025-02-03T04:05:06.000","descriptions":[{"lang":"ko","value":"ignore"},{"lang":"en","value":"English description"}],"metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"vectorString":"secondary"}},{"type":"Primary","cvssData":{"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},"references":[{"url":"https://example.com/1"}]}},
 {"cve":{"id":"CVE-2025-5678","descriptions":[{"lang":"en","value":"Second CVE"}],"metrics":{"cvssMetricV2":[{"type":"Secondary","cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]}}}
]}`

func nvdGzip(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestNVDUpdateAliasSeverityAndConditionalGET(t *testing.T) {
	body := nvdGzip(t, tinyNVDFeed)
	osv := fixtureZip(t, map[string]string{"debian.json": `{"id":"DEBIAN-CVE-2025-1234","aliases":["CVE-2025-1234"],"affected":[{"package":{"ecosystem":"Debian:13","name":"demo"},"versions":["1"]}]}`})
	tracker := `{"tracker-demo":{"CVE-2025-1234":{"releases":{"trixie":{"status":"open","urgency":"not yet assigned"}}}}}`
	var conditional atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"fixture"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"fixture"`)
		switch r.URL.Path {
		case "/nvdcve-2.0-2025.json.gz", "/nvdcve-2.0-modified.json.gz":
			_, _ = w.Write(body)
		case "/Debian/all.zip":
			_, _ = w.Write(osv)
		case "/tracker.json":
			_, _ = w.Write([]byte(tracker))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := httpx.New(time.Minute)
	client.HTTP.Transport = srv.Client().Transport
	opts := Options{Sources: []string{"osv", "debian", "nvd"}, Ecosystems: []string{"Debian"}, OSVBaseURL: srv.URL, DebianURL: srv.URL + "/tracker.json", Client: client}
	nvd := NVDOptions{Years: "2025", BaseURL: srv.URL}
	dir := filepath.Join(t.TempDir(), "db")
	for i := 0; i < 2; i++ {
		meta, err := Update(context.Background(), dir, opts, nvd)
		if err != nil {
			t.Fatal(err)
		}
		if meta.Records != 3 {
			t.Fatalf("records = %d", meta.Records)
		}
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"demo", "tracker-demo"} {
			records, err := st.Lookup("Debian", name)
			if err != nil || len(records) != 1 {
				st.Close()
				t.Fatalf("lookup %s: %+v, %v", name, records, err)
			}
			r := records[0]
			if len(r.Severity) != 1 || r.Severity[0].Score != aliasCriticalVector {
				t.Fatalf("severity = %+v", r.Severity)
			}
			source := r.Database["severity_source"]
			if source != "alias:CVE-2025-1234" && source != "nvd" {
				t.Fatalf("provenance = %v", source)
			}
		}
		// Severity-only NVD records survive the SQLite build without creating
		// any package matches; ID lookup still exposes them.
		standalone, err := LookupIDContext(context.Background(), st, "CVE-2025-5678")
		if err != nil || len(standalone) != 1 || len(standalone[0].Affected) != 0 || standalone[0].Source != "nvd" {
			t.Fatalf("standalone: %+v, %v", standalone, err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if conditional.Load() != 4 {
		t.Fatalf("conditional GET count = %d", conditional.Load())
	}
	// Download caps also apply to NVD through the shared update engine.
	opts.MaxFeedBytes = 8
	opts.Sources = []string{"nvd"}
	_, err := Update(context.Background(), filepath.Join(t.TempDir(), "oversized"), opts, nvd)
	if err == nil {
		t.Fatal("oversized download accepted")
	}
}

func TestNVDConversionAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.gz")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, nvdGzip(t, body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(tinyNVDFeed)
	var records []*Record
	if err := parseNVDFeed(context.Background(), path, func(r *Record) error { records = append(records, r); return nil }, 1<<20); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Summary != "English description" || records[0].Published != "2025-01-02T03:04:05.123Z" || records[0].Modified != "2025-02-03T04:05:06Z" || records[1].Severity[0].Type != "CVSS_V2" {
		t.Fatalf("conversion = %+v", records)
	}
	stop := errors.New("stop")
	if err := parseNVDFeed(context.Background(), path, func(*Record) error { return stop }, 1<<20); !errors.Is(err, stop) {
		t.Fatalf("emit error = %v", err)
	}
	if err := parseNVDFeed(context.Background(), path, func(*Record) error { return nil }, 10); err == nil {
		t.Fatal("expanded cap ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseNVDFeed(ctx, path, func(*Record) error { return nil }, 1<<20); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	for _, body := range []string{`{}`, `{"vulnerabilities":{}}`, `{"vulnerabilities":[{"cve":{"id":"GHSA-X"}}]}`, tinyNVDFeed + `{}`, strings.TrimSuffix(tinyNVDFeed, "}")} {
		write(body)
		if err := parseNVDFeed(context.Background(), path, func(*Record) error { return nil }, 1<<20); err == nil {
			t.Fatalf("invalid feed accepted: %s", body)
		}
	}
	corrupted := nvdGzip(t, tinyNVDFeed)
	corrupted[len(corrupted)-8] ^= 1
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if err := parseNVDFeed(context.Background(), path, func(*Record) error { return nil }, 1<<20); err == nil {
		t.Fatal("invalid gzip checksum accepted")
	}
	v := nvdCVE{ID: "CVE-2025-1111"}
	v.Descriptions = append(v.Descriptions, struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{"en", strings.Repeat("한", 500)})
	for range 7 {
		v.References = append(v.References, struct {
			URL string `json:"url"`
		}{"https://example.com"})
	}
	metric := func(vector string) nvdMetric { var m nvdMetric; m.Data.Vector = vector; return m }
	v.Metrics.V40 = []nvdMetric{metric("v4")}
	v.Metrics.V31 = []nvdMetric{metric("v31")}
	v.Metrics.V30 = []nvdMetric{metric("v30")}
	v.Metrics.V2 = []nvdMetric{metric("v2")}
	got := convertNVD(v)
	if len(got.Summary) > 1024 || !strings.HasSuffix(got.Summary, "...") || len(got.References) != 5 || len(got.Severity) != 4 || got.Severity[0].Type != "CVSS_V4" || got.Severity[2].Score != "v30" {
		t.Fatalf("bounded conversion: %+v", got)
	}
}

func TestNVDYearsAndOptIn(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		spec string
		want []int
	}{{"", []int{2024, 2025, 2026}}, {"2024-2026", []int{2024, 2025, 2026}}, {"2026,2024,2024", []int{2024, 2026}}, {"2024-2025,2026", []int{2024, 2025, 2026}}} {
		got, err := parseNVDYears(tt.spec, now)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("years %q = %v,%v", tt.spec, got, err)
		}
	}
	for _, spec := range []string{"2001", "2027", "2026-2024", "2024,", "x", "2024-2025-2026"} {
		if _, err := parseNVDYears(spec, now); err == nil {
			t.Fatalf("invalid years accepted: %q", spec)
		}
	}
	for _, source := range DefaultSources {
		if source == SourceNVD {
			t.Fatal("NVD in defaults")
		}
	}
	source, ok := LookupSource("nvd")
	if !ok {
		t.Fatal("NVD not registered")
	}
	feeds, err := source.Feeds(&Options{})
	if err != nil || len(feeds) != 4 || feeds[3].URL != DefaultNVDBaseURL+"/nvdcve-2.0-modified.json.gz" {
		t.Fatalf("default feeds = %+v,%v", feeds, err)
	}
}
