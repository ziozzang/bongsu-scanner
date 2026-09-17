package match

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type almaLinuxFeedTransport struct {
	data   []byte
	cached int
}

func (f *almaLinuxFeedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("If-None-Match") == `"alma-fixture"` {
		f.cached++
		return &http.Response{StatusCode: http.StatusNotModified, Header: http.Header{}, Body: http.NoBody}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(f.data)), Header: http.Header{"Etag": {`"alma-fixture"`}}, Body: io.NopCloser(bytes.NewReader(f.data))}, nil
}

func TestAlmaLinuxIngestionMatchAndCache(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, raw := range map[string]string{
		"alma.json": `{"id":"ALSA-2026:0002","summary":"Moderate: tar security update","related":["CVE-2025-45582"],"affected":[{"package":{"ecosystem":"AlmaLinux:9","name":"tar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1.el9"}]}]}]}`,
		"cve.json":  `{"id":"CVE-2025-45582","severity":[{"type":"CVSS_V3","score":"9.8"}],"affected":[{"package":{"ecosystem":"AlmaLinux:9","name":"donor"},"versions":["1"]}]}`,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	transport := &almaLinuxFeedTransport{data: buf.Bytes()}
	client := httpx.New(time.Second)
	client.HTTP.Transport = transport
	dir := filepath.Join(t.TempDir(), "db")
	opts := vulndb.Options{Sources: []string{vulndb.SourceOSV}, Ecosystems: []string{"AlmaLinux:9"}, OSVBaseURL: "https://alma.example.invalid", Client: client, NoKeepRaw: true}
	for _, phase := range []string{"fresh", "cached"} {
		t.Run(phase, func(t *testing.T) {
			if _, err := vulndb.Update(context.Background(), dir, opts); err != nil {
				t.Fatal(err)
			}
			st, err := vulndb.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			records, err := st.Lookup("AlmaLinux:9", "tar")
			if err != nil || len(records) != 1 {
				t.Fatalf("lookup: %+v, %v", records, err)
			}
			rec := records[0]
			if !slices.Equal(rec.Aliases, []string{"CVE-2025-45582"}) || !slices.Equal(rec.Related, []string{"CVE-2025-45582"}) {
				t.Errorf("CVE identity: %+v", rec)
			}
			subjects := []Subject{{Ref: "tar", Type: "rpm", Ecosystem: "AlmaLinux", Release: "9", Name: "tar", Version: "1.0-1.el9"}}
			for _, policy := range []string{"", "distro", "cvss", "max"} {
				report, err := Run(context.Background(), st, subjects, Options{SeveritySource: policy})
				if err != nil || len(report.Findings) != 1 {
					t.Fatalf("match: %+v, %v", report, err)
				}
				f := report.Findings[0]
				want := "MEDIUM"
				if policy == "cvss" || policy == "max" {
					want = "CRITICAL"
				}
				if f.ID != "CVE-2025-45582" || f.Severity != want || f.DistroSeverity != "medium" || f.Score != 9.8 {
					t.Errorf("policy=%q finding=%+v; want CVE id, severity %s, distro medium, CVSS 9.8", policy, f, want)
				}
			}
		})
	}
	if transport.cached != 1 {
		t.Errorf("cached requests = %d, want 1", transport.cached)
	}
}
