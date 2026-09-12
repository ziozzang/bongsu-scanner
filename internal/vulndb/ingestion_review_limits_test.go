package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestReviewOSVZipLimits(t *testing.T) {
	body := osvFixture("CVE-2026-1234", "npm", "curl")
	p := filepath.Join(t.TempDir(), "feed.zip")
	if err := os.WriteFile(p, fixtureZip(t, map[string]string{"a.json": body, "b.json": body}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		entries int
		bytes   uint64
		filter  bool
		want    string
	}{
		{"entry-count", 1, 1 << 30, false, "exceeds 1 entries"},
		{"expanded-bytes", 2, uint64(len(body)*2 - 1), false, "total uncompressed bytes"},
		{"filtered-count", 1, 1 << 30, true, "exceeds 1 entries"},
		{"filtered-bytes", 2, uint64(len(body)*2 - 1), true, "total uncompressed bytes"},
		{"exact-boundary", 2, uint64(len(body) * 2), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitted := 0
			n, err := parseOSVZipBounded(context.Background(), p, SourceOSV, func(string) bool { return !tc.filter }, func(*Record) error { emitted++; return nil }, nil, tc.entries, tc.bytes)
			if tc.want == "" {
				if err != nil || n != 2 || emitted != 2 {
					t.Fatalf("n=%d emitted=%d err=%v", n, emitted, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || n != 0 || emitted != 0 {
				t.Fatalf("archive was not rejected before emission: n=%d emitted=%d err=%v", n, emitted, err)
			}
		})
	}
}

func TestReviewOSVProductionExpandedLimit(t *testing.T) {
	for _, sizes := range [][]uint64{
		{osvMaxUncompressedBytes, 1},
		{1, math.MaxUint64}, // Addition must not wrap around the budget.
	} {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for i, size := range sizes {
			// Raw headers exercise limits without allocating gigabytes. Ignored
			// members still count toward archive-wide resource limits.
			if _, err := zw.CreateRaw(&zip.FileHeader{Name: fmt.Sprintf("%d.txt", i), Method: zip.Store, UncompressedSize64: size}); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "feed.zip")
		if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := parseOSVZip(context.Background(), p, SourceOSV, nil, func(*Record) error { t.Fatal("unexpected record"); return nil }, nil)
		if err == nil || !strings.Contains(err.Error(), "total uncompressed bytes") {
			t.Fatalf("oversized archive accepted: %v", err)
		}
	}
}

func TestReviewStreamingCacheLimits(t *testing.T) {
	v := reviewOSV(t, "npm")
	r, _ := ConvertOSV(&v, SourceOSV)
	addProvenance(r, RecordSource{Name: SourceOSV, URL: "https://example.org/feed"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	recordBytes := len(b) + 1
	for _, tc := range []struct {
		name                    string
		maxBytes                int64
		maxRecord               int
		wantCount, wantAttempts int
		wantError               bool
	}{
		{"total-exact", int64(recordBytes * 2), recordBytes + 1, 2, 2, false},
		{"total-exceeded", int64(recordBytes*2 - 1), recordBytes + 1, 1, 2, true},
		{"record-exceeded", 1 << 30, recordBytes, 0, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			feed := Feed{Source: SourceOSV, URL: "https://example.org/feed", Parse: func(_ context.Context, _ string, _ int64, emit Emit, _ func(string)) error {
				for i := 0; i < 2; i++ {
					attempts++
					if err := emit(r); err != nil {
						return err
					}
				}
				return nil
			}}
			p := filepath.Join(t.TempDir(), "cache.gz")
			n, err := streamFeedCache(context.Background(), feed, "unused", p, 0, nil, tc.maxBytes, tc.maxRecord)
			if n != tc.wantCount || attempts != tc.wantAttempts || (err != nil) != tc.wantError {
				t.Fatalf("n=%d attempts=%d err=%v", n, attempts, err)
			}
			if tc.wantError {
				if !strings.Contains(err.Error(), "size limit") {
					t.Fatal(err)
				}
				if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("partial cache retained: %v", err)
				}
			} else {
				read := 0
				if err := readRecords(p, func(*Record) error { read++; return nil }); err != nil || read != 2 {
					t.Fatalf("cache unreadable: count=%d err=%v", read, err)
				}
			}
		})
	}
}

func TestReviewAlpineSerializationStable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alpine.json")
	if err := os.WriteFile(p, []byte(`{"packages":[{"pkg":{"name":"zlib","secfixes":{"1.10-r0":["CVE-2026-1234"],"1.2-r10":["CVE-2026-1234"],"1.2-r2":["CVE-2026-1234"],"0":["CVE-2026-1234"]}}},{"pkg":{"name":"curl","secfixes":{"2.0-r0":["CVE-2026-1234"]}}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var first []byte
	for i := 0; i < 30; i++ {
		if err := parseAlpineSecDB(context.Background(), p, "v3.20", "main", func(r *Record) error {
			var order []string
			for _, a := range r.Affected {
				order = append(order, a.Package+"/"+firstFixedVersion(a))
			}
			if !reflect.DeepEqual(order, []string{"curl/2.0-r0", "zlib/1.2-r2", "zlib/1.2-r10", "zlib/1.10-r0"}) {
				t.Fatalf("wrong Alpine ordering: %v", order)
			}
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if i == 0 {
				first = b
			} else if !bytes.Equal(first, b) {
				t.Fatal("nondeterministic Alpine JSON")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReviewNormalizeDebianRelease(t *testing.T) {
	for input, want := range map[string]string{"sid": "sid", "unstable": "sid", " sid ": "sid", "bookworm": "12", "trixie": "13", "13": "13", "future": "future", "": ""} {
		if got := NormalizeDebianRelease(input); got != want {
			t.Errorf("%q: got %q want %q", input, got, want)
		}
	}
}

func TestReviewUpdatePreservesNativeUrgencyAndSeverity(t *testing.T) {
	osv := []byte(`{"id":"CVE-2026-1234","affected":[{"package":{"ecosystem":"Debian:sid","name":"curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}],"database_specific":{"urgency":"high","osv":true},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`)
	archive := fixtureZip(t, map[string]string{"advisory.json": string(osv)})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"fixture"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"fixture"`)
		if r.URL.Path == "/tracker" {
			_, _ = w.Write([]byte(`{"curl":{"CVE-2026-1234":{"releases":{"sid":{"status":"resolved","fixed_version":"2.0","urgency":"unimportant"}}}}}`))
		} else {
			_, _ = w.Write(archive)
		}
	}))
	defer srv.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = srv.Client().Transport
	for _, sources := range [][]string{{SourceOSV, SourceDebian}, {SourceDebian, SourceOSV}} {
		dir := filepath.Join(t.TempDir(), "db")
		opts := Options{Sources: sources, Ecosystems: []string{"Debian"}, OSVBaseURL: srv.URL, DebianURL: srv.URL + "/tracker", Client: client}
		for i := 0; i < 2; i++ {
			if _, err := Update(context.Background(), dir, opts); err != nil {
				t.Fatal(err)
			}
			st, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			rs, err := st.Lookup("Debian", "curl")
			st.Close()
			if err != nil || len(rs) != 1 || len(rs[0].Affected) != 1 {
				t.Fatalf("merged lookup: %+v %v", rs, err)
			}
			a := rs[0].Affected[0]
			if a.Ecosystem != "Debian:sid" || a.Database["urgency"] != "unimportant" || a.Database["osv"] != true || len(a.Severity) != 1 {
				t.Fatalf("sources=%v update=%d lost metadata: %+v", sources, i, a)
			}
		}
	}
}
