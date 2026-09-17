package vulndb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestFeedCacheRevalidatesExpandedSize(t *testing.T) {
	for _, source := range []string{SourceOSV, SourceGHSA} {
		for _, keepRaw := range []bool{true, false} {
			for _, legacy := range []bool{true, false} {
				t.Run(source+"/raw="+fmtBool(keepRaw)+"/legacy="+fmtBool(legacy), func(t *testing.T) {
					body := osvFixture("CVE-2026-1234", "RubyGems", "example")
					// Ignored members still count against the original archive expansion limit.
					padding := strings.Repeat(" ", 4096)
					archive := fixtureZip(t, map[string]string{"a.json": body, "README": padding})
					client := httpx.New(time.Second)
					requests, conditional := 0, 0
					client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
						requests++
						if req.Header.Get("If-None-Match") != "" {
							conditional++
							return &http.Response{StatusCode: 304, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
						}
						return &http.Response{StatusCode: 200, ContentLength: int64(len(archive)), Header: http.Header{"Etag": {`"fixture"`}}, Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
					})
					opts := Options{Client: client, MaxFeedBytes: 1 << 20, MaxFeedUncompressedBytes: 1 << 20, NoKeepRaw: !keepRaw}
					parsed := 0
					feed := Feed{Source: source, Key: "fixture", File: "fixture.zip", URL: "https://example.org/feed.zip", Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
						parsed++
						_, err := parseOSVZipBounded(ctx, p, source, nil, emit, progress, 100, opts.maxFeedUncompressedBytes())
						return err
					}}
					first := t.TempDir()
					spool, err := newIngestionSpool(first)
					if err != nil {
						t.Fatal(err)
					}
					m, err := updateFeed(context.Background(), t.TempDir(), first, feed, nil, opts, time.Now(), spool)
					if closeErr := spool.close(); err != nil || closeErr != nil {
						t.Fatalf("initial update: %v %v", err, closeErr)
					}
					metadataPath := filepath.Join(first, "cache", source, "fixture.jsonl.gz.meta.json")
					if legacy {
						if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
					} else {
						data, err := os.ReadFile(metadataPath)
						if err != nil {
							t.Error("expanded-size cache metadata missing:", err)
						} else {
							var meta struct {
								ExpandedBytes uint64 `json:"expanded_bytes"`
							}
							if err := json.Unmarshal(data, &meta); err != nil || meta.ExpandedBytes != uint64(len(body)+len(padding)) {
								t.Errorf("metadata=%s err=%v", data, err)
							}
						}
					}
					opts.MaxFeedUncompressedBytes = int64(len(body) + 1)
					second := t.TempDir()
					next, err := newIngestionSpool(second)
					if err != nil {
						t.Fatal(err)
					}
					defer next.close()
					_, err = updateFeed(context.Background(), first, second, feed, map[string]SourceMeta{source + "\x00" + feed.URL: m}, opts, time.Now(), next)
					if err == nil || !strings.Contains(err.Error(), "--max-feed-uncompressed") {
						t.Fatalf("lowered expansion limit bypassed: %v", err)
					}
					wantConditional := 0
					if keepRaw {
						wantConditional = 1
					}
					if requests != 2 || conditional != wantConditional || parsed != 2 {
						t.Errorf("requests=%d conditional=%d parses=%d", requests, conditional, parsed)
					}
				})
			}
		}
	}
}

func fmtBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestFeedCacheRetainsExpandedSizeAcross304(t *testing.T) {
	body := osvFixture("CVE-2026-1234", "RubyGems", "example")
	archive := fixtureZip(t, map[string]string{"a.json": body})
	client := httpx.New(time.Second)
	requests := 0
	client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests > 1 {
			if req.Header.Get("If-None-Match") == "" {
				t.Error("valid cache forced download")
			}
			return &http.Response{StatusCode: 304, Header: http.Header{}, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(archive)), Header: http.Header{"Etag": {`"fixture"`}}, Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
	})
	opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"RubyGems"}, Client: client, MaxFeedUncompressedBytes: int64(len(body) + 1), NoKeepRaw: true}
	dir := filepath.Join(t.TempDir(), "db")
	for i := 0; i < 3; i++ {
		if i > 0 {
			opts.MaxFeedUncompressedBytes = int64(len(body))
		}
		meta, err := Update(context.Background(), dir, opts)
		if err != nil || meta.Records != 1 {
			t.Fatalf("update %d: %+v %v", i, meta, err)
		}
		files, err := filepath.Glob(filepath.Join(dir, "cache", SourceOSV, "*.meta.json"))
		if err != nil || len(files) != 1 {
			t.Fatalf("cache metadata lost on update %d: %v %v", i, files, err)
		}
		var cached struct {
			ExpandedBytes uint64 `json:"expanded_bytes"`
		}
		if err := readJSON(files[0], &cached); err != nil || cached.ExpandedBytes != uint64(len(body)) {
			t.Fatalf("metadata: %+v %v", cached, err)
		}
	}
}
