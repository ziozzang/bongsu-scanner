package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
	"github.com/ziozzang/bongsu-scanner/internal/version"
)

type rubysecTransport func(*http.Request) (*http.Response, error)

func (f rubysecTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRubysecUpdateLookupConditional(t *testing.T) {
	if _, ok := LookupSource("rubysec"); !ok {
		t.Fatal("rubysec source is not registered")
	}
	for _, name := range DefaultSources {
		if name == "rubysec" {
			t.Fatal("rubysec must be opt-in")
		}
	}
	archive := fixtureZip(t, map[string]string{
		"repo/gems/resolv/CVE-2026-80212.yml": `---
gem: resolv
cve: 2026-80212
ghsa: x2vh-ff4w-v64c
osvdb: 12345
title: 'Memory exhaustion: DNS'
date: 2026-08-27
description: |
  First line.
  Second line.
url: https://example.org/advisory
related:
  url:
    - 'https://example.org/details#impact'
cvss_v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
cvss_v4:
  - 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'
patched_versions:
  - '>= 0.3.2'
`,
		"repo/gems/branch/GHSA-abcd-efgh-ijkl.yml": `ghsa: abcd-efgh-ijkl
title: Branch fix
description: >
  Folded
  description.
unaffected_versions:
- '< 3.2.1'
patched_versions:
- '~> 3.2.4'
`,
		"repo/gems/unknown/local.yml": `title: Unmapped
patched_versions:
  - '>= 2.0'
  - '~> 1.2, >= 1.2.3'
`,
		"repo/rubies/ruby/ignored.yml": "not YAML",
	})
	var requests, conditional atomic.Int32
	client := httpx.New(time.Minute)
	client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		if req.URL.String() != "https://github.com/rubysec/ruby-advisory-db/archive/refs/heads/master.zip" {
			t.Errorf("unexpected URL: %s", req.URL)
		}
		status, body := http.StatusOK, string(archive)
		if req.Header.Get("If-None-Match") == `"rubysec-fixture"` {
			conditional.Add(1)
			status, body = http.StatusNotModified, ""
		}
		return &http.Response{StatusCode: status, ContentLength: int64(len(body)), Header: http.Header{"Etag": {`"rubysec-fixture"`}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	dir := filepath.Join(t.TempDir(), "db")
	opts := Options{Sources: []string{"rubysec"}, Client: client}
	for i := 0; i < 2; i++ {
		meta, err := Update(context.Background(), dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		if meta.Records != 3 {
			t.Fatalf("records = %d, want 3", meta.Records)
		}
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer st.Close()
			for _, gem := range []string{"resolv", "branch", "unknown"} {
				rs, err := st.Lookup("RubyGems", gem)
				if err != nil || len(rs) != 1 {
					t.Fatalf("lookup %s: %+v, %v", gem, rs, err)
				}
				r := rs[0]
				if r.Source != "rubysec" || len(r.Affected) != 1 {
					t.Fatalf("record: %+v", r)
				}
				switch gem {
				case "resolv":
					if r.ID != "CVE-2026-80212" || len(r.Aliases) != 3 || r.Aliases[2] != "OSVDB-12345" || r.Summary != "Memory exhaustion: DNS" || r.Details != "First line.\nSecond line.\n" || r.Published != "2026-08-27T00:00:00Z" || len(r.Severity) != 2 || len(r.References) != 2 {
						t.Fatalf("metadata: %+v", r)
					}
					rubysecAssertAffected(t, r.Affected[0], map[string]bool{"0.3.1": true, "0.3.2": false})
				case "branch":
					if r.ID != "GHSA-abcd-efgh-ijkl" || r.Details != "Folded description.\n" {
						t.Fatalf("branch: %+v", r)
					}
					rubysecAssertAffected(t, r.Affected[0], map[string]bool{"3.2.0": false, "3.2.1": true, "3.2.3": true, "3.2.4": false, "3.3.0": false})
				case "unknown":
					a := r.Affected[0]
					if r.ID != "RUBYSEC-unknown-local" || len(a.Ranges) != 0 || len(a.Versions) != 0 || a.Database["rubysec_unmapped"] != "~> 1.2, >= 1.2.3" {
						t.Fatalf("unmapped: %+v", r)
					}
				}
			}
		}()
	}
	if requests.Load() != 2 || conditional.Load() != 1 {
		t.Fatalf("requests=%d, conditional=%d", requests.Load(), conditional.Load())
	}
}

func rubysecAssertAffected(t *testing.T, a Affected, cases map[string]bool) {
	t.Helper()
	for installed, want := range cases {
		got := false
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" || len(rg.Events) != 2 {
				t.Fatalf("unexpected range: %+v", rg)
			}
			lo, err := version.Compare("RubyGems", installed, rg.Events[0].Introduced)
			if err != nil {
				t.Fatal(err)
			}
			hi, err := version.Compare("RubyGems", installed, rg.Events[1].Fixed)
			if err != nil {
				t.Fatal(err)
			}
			got = got || lo >= 0 && hi < 0
		}
		if got != want {
			t.Errorf("%s affected=%v, want %v; ranges=%+v", installed, got, want, a.Ranges)
		}
	}
}

func TestRubysecRanges(t *testing.T) {
	for _, tc := range []struct {
		name                string
		patched, unaffected []string
		cases               map[string]bool
	}{
		{"resolv branches", []string{"~> 0.3.2", ">= 0.7.2"}, nil, map[string]bool{"0.3.1": true, "0.3.2": false, "0.3.9": false, "0.4.0": true, "0.7.1": true, "0.7.2": false}},
		{"branch only", []string{"~> 3.2.4"}, nil, map[string]bool{"3.1.9": false, "3.2.0": true, "3.2.3": true, "3.2.4": false, "3.3.0": false}},
		{"unaffected boundary", []string{">= 2.0"}, []string{"< 1.0", "< 1.2"}, map[string]bool{"1.1": false, "1.2": true, "2.0": false}},
		{"duplicate branches", []string{"~> 3.2.6", "~> 3.2.4", ">= 4.0"}, nil, map[string]bool{"3.2.3": true, "3.2.4": false, "3.2.5": false, "3.3.0": true}},
		{"earliest terminal fix", []string{">= 3.2.2", "~> 3.2.4", ">= 4.0"}, nil, map[string]bool{"3.2.1": true, "3.2.2": false, "3.2.3": false, "3.3.0": false}},
		{"four component numeric fix", []string{">= 1.2.3.4"}, nil, map[string]bool{"1.2.3.3": true, "1.2.3.4": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ranges, why := rubysecRanges(tc.patched, tc.unaffected)
			if why != "" {
				t.Fatal(why)
			}
			rubysecAssertAffected(t, Affected{Ranges: ranges}, tc.cases)
		})
	}
	for _, req := range []string{"~> 1.2, >= 1.2.3", "~> 1.2", ">= 1.0.0.rc1", "!= 1.0", "< 1.0", "~> 1.999999999999999999999.1"} {
		ranges, why := rubysecRanges([]string{">= 5.0", req}, nil)
		if len(ranges) != 0 || why != req {
			t.Errorf("%q: %+v %q", req, ranges, why)
		}
	}
	for _, unaffected := range [][]string{{">= 1.0"}, {"~> 1.2.3"}} {
		if ranges, why := rubysecRanges([]string{">= 5.0"}, unaffected); len(ranges) != 0 || why == "" {
			t.Fatalf("unsafe unaffected mapping: %+v %q", ranges, why)
		}
	}
	if ranges, why := rubysecRanges(nil, nil); len(ranges) != 0 || why == "" {
		t.Fatal("missing patch must be unknown")
	}
	if ranges, why := rubysecRanges([]string{">= 2.0", ""}, nil); len(ranges) != 0 || why != "empty requirement" {
		t.Fatal("empty requirement must invalidate otherwise usable ranges")
	}
}

func TestRubysecYAMLSubset(t *testing.T) {
	if got := rubysecBlock([]string{"\t", "\t"}, ">"); got != "" {
		t.Fatalf("blank block: %q", got)
	}
	fields, err := readRubysecYAML("---\r\ntitle: 'Gem''s title' # comment\r\ndescription: >-\r\n  First line\r\n  continued.\r\n\r\n  Second paragraph.\r\nrelated:\r\n- https://example.org/#fragment\r\npatched_versions:\r\n- \">= 1.0\" # comment\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if fields["title"][0] != "Gem's title" || fields["description"][0] != "First line continued.\nSecond paragraph." || fields["related"][0] != "https://example.org/#fragment" || fields["patched_versions"][0] != ">= 1.0" {
		t.Fatalf("fields: %+v", fields)
	}
	fields, err = readRubysecYAML("title: A long\n  wrapped title\ndescription: \"A \\\"quoted\\\" description\\nline\"\ncvss_v3: 7.5\n")
	if err != nil || fields["title"][0] != "A long wrapped title" || fields["description"][0] != "A \"quoted\" description\nline" {
		t.Fatalf("fields: %+v, %v", fields, err)
	}
	r, err := rubysecRecord("example", "local", fields)
	if err != nil || len(r.Severity) != 0 {
		t.Fatalf("numeric CVSS must be omitted: %+v, %v", r, err)
	}
	for _, data := range []string{"title: &anchor value", "title: *anchor", "title: 'unclosed", "title: one\ntitle: two", "patched_versions:\n  nested: broken", "not YAML"} {
		if _, err := readRubysecYAML(data); err == nil {
			t.Errorf("accepted unsupported YAML %q", data)
		}
	}
}

func TestRubysecFeedLimitsAndErrors(t *testing.T) {
	source, ok := LookupSource("rubysec")
	if !ok {
		t.Fatal("missing source")
	}
	for _, limit := range []int64{0, 1024, 128 << 20} {
		feeds, err := source.Feeds(&Options{MaxFeedBytes: limit})
		if err != nil || len(feeds) != 1 {
			t.Fatalf("feeds: %+v %v", feeds, err)
		}
		want := RubysecMaxBytes
		if limit > 0 && limit < want {
			want = limit
		}
		if feeds[0].MaxBytes != want || !reflect.DeepEqual(feeds[0].Ecosystems, []string{"RubyGems"}) {
			t.Fatalf("feed: %+v", feeds[0])
		}
	}
	client := httpx.New(time.Second)
	client.HTTP.Transport = rubysecTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: RubysecMaxBytes + 1, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	feeds, _ := source.Feeds(&Options{})
	if _, err := fetchFeed(context.Background(), client, feeds[0], nil, filepath.Join(t.TempDir(), "raw.zip"), false, time.Now()); !errors.Is(err, httpx.ErrTooLarge) {
		t.Fatalf("oversized archive: %v", err)
	}

	filename := filepath.Join(t.TempDir(), "feed.zip")
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(filename, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(fixtureZip(t, map[string]string{"repo/gems/example/local.yml": "title: Advisory\npatched_versions:\n- '>= 1.0'"}))
	sentinel := errors.New("stop")
	if err := parseRubysecZip(context.Background(), filename, func(*Record) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("emit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := parseRubysecZip(ctx, filename, func(*Record) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	for _, data := range [][]byte{
		[]byte("not a ZIP"),
		fixtureZip(t, map[string]string{"repo/gems/example/local.yml": "title: 'unclosed"}),
		fixtureZip(t, map[string]string{"repo/gems/example/local.yml": strings.Repeat("x", rubysecMemberMaxBytes+1)}),
	} {
		write(data)
		if err := parseRubysecZip(context.Background(), filename, func(*Record) error { return nil }); err == nil {
			t.Fatal("accepted malformed/oversized archive")
		}
	}
	// Stored member with deliberately wrong CRC must fail after reading EOF.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	body := "title: CRC test\n"
	w, err := zw.CreateRaw(&zip.FileHeader{Name: "repo/gems/example/local.yml", Method: zip.Store, CRC32: 1, CompressedSize64: uint64(len(body)), UncompressedSize64: uint64(len(body))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	write(buf.Bytes())
	if err = parseRubysecZip(context.Background(), filename, func(*Record) error { return nil }); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("CRC: %v", err)
	}
}
