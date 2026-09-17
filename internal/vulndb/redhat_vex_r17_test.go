package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func TestR17VEXStructureLimits(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement string }{
		{"branches", `"branches":[{"branches":[`, `"branches":[` + strings.Repeat(`{},`, 100001) + `{"branches":[`},
		{"relationships", `"relationships":[`, `"relationships":[` + strings.Repeat(`{},`, 100001)},
		{"product_ids", `"product_ids":["affected"]`, `"product_ids":[` + strings.Repeat(`"ignored",`, 200001) + `"affected"]`},
		{"product_status", `"known_affected":["affected","ignored"]`, `"known_affected":[` + strings.Repeat(`"ignored",`, 200001) + `"affected"]`},
		{"score_products", `"products":["ignored"]`, `"products":[` + strings.Repeat(`"ignored",`, 200001) + `"ignored"]`},
		{"threat_product_ids", `"product_ids":["fixed","fixed-arch"]`, `"product_ids":[` + strings.Repeat(`"ignored",`, 200001) + `"fixed"]`},
		{"remediations", `"remediations":[`, `"remediations":[` + strings.Repeat(`{},`, 100001)},
		{"threats", `"threats":[`, `"threats":[` + strings.Repeat(`{},`, 100001)},
		{"scores", `"scores":[`, `"scores":[` + strings.Repeat(`{},`, 100001)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := vexArchive(t, strings.Replace(vexFixture, tc.old, tc.replacement, 1))
			var log string
			count := 0
			err := parseRedHatVEX(context.Background(), path, 8<<20, 8<<20, func(*Record) error { count++; return nil }, func(s string) { log = s })
			if err != nil || count != 0 || !strings.Contains(log, "skipped_malformed=1") {
				t.Fatalf("count=%d log=%s err=%v", count, log, err)
			}
		})
	}
}

func TestR17VEXPrecedence(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		doc := vexDecode(t, vexFixture)
		v := &doc.Vulnerabilities[0]
		v.Status.Affected = append(v.Status.Affected, "fixed", "safe", "investigate")
		v.Status.Investigating = append(v.Status.Investigating, "fixed", "safe", "affected")
		v.Status.NotAffected = append(v.Status.NotAffected, "fixed")
		v.Remediations = []vexStatement{
			{Category: "no_fix_planned", Details: "Will not fix", Products: []string{"affected"}},
			{Category: "none_available", Details: "Affected", Products: []string{"affected"}},
		}
		if reverse {
			v.Remediations[0], v.Remediations[1] = v.Remediations[1], v.Remediations[0]
		}
		r, err := convertRedHatVEX(context.Background(), doc)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, a := range r.Affected {
			counts[a.Package]++
			if a.Package == "unfixed" && a.Database["redhat_status"] != "will-not-fix" {
				t.Errorf("remediation: %+v", a)
			}
			if a.Package == "safe" && a.Database["redhat_status"] != "not-affected" {
				t.Errorf("safe: %+v", a)
			}
		}
		if counts["example-libs"] != 1 || counts["safe"] != 1 || counts["unfixed"] != 1 || counts["investigate"] != 1 {
			t.Errorf("conflicting statuses: %v", counts)
		}
		if r.Database["redhat_status_conflicts"] == nil {
			t.Error("contradictions not counted")
		}
	}
}

func TestR17VEX304ExpansionLimit(t *testing.T) {
	for _, keepRaw := range []bool{true, false} {
		t.Run(fmtBool(keepRaw), func(t *testing.T) {
			archive, err := os.ReadFile(vexArchive(t, vexFixture))
			if err != nil {
				t.Fatal(err)
			}
			client := httpx.New(time.Second)
			client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("If-None-Match") != "" {
					return &http.Response{StatusCode: 304, Header: http.Header{}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: 200, ContentLength: int64(len(archive)), Header: http.Header{"Etag": {`"vex"`}}, Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
			})
			opts := Options{Client: client, MaxFeedBytes: 1 << 20, MaxFeedUncompressedBytes: 1 << 20, NoKeepRaw: !keepRaw}
			feed := Feed{Source: SourceRedHatVEX, Key: "vex", File: "vex.tar.zst", URL: "https://example.org/vex.tar.zst", Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
				return parseRedHatVEX(ctx, p, opts.maxFeedUncompressedBytes(), 16<<20, emit, progress)
			}}
			first := t.TempDir()
			spool, err := newIngestionSpool(first)
			if err != nil {
				t.Fatal(err)
			}
			m, err := updateFeed(context.Background(), t.TempDir(), first, feed, nil, opts, time.Now(), spool)
			if closeErr := spool.close(); err != nil || closeErr != nil {
				t.Fatalf("initial: %v %v", err, closeErr)
			}
			opts.MaxFeedUncompressedBytes = 512
			next := t.TempDir()
			spool, err = newIngestionSpool(next)
			if err != nil {
				t.Fatal(err)
			}
			defer spool.close()
			_, err = updateFeed(context.Background(), first, next, feed, map[string]SourceMeta{SourceRedHatVEX + "\x00" + feed.URL: m}, opts, time.Now(), spool)
			if err == nil || !strings.Contains(err.Error(), "--max-feed-uncompressed") {
				t.Fatalf("lowered limit bypassed: %v", err)
			}
			var meta feedExpansionMeta
			if err := readJSON(filepath.Join(first, "cache", SourceRedHatVEX, "vex.jsonl.gz.meta.json"), &meta); err != nil || meta.ExpandedBytes < uint64(len(vexFixture)) {
				t.Fatalf("meta=%+v err=%v", meta, err)
			}
		})
	}
}

func TestR17VEXStreamingParity(t *testing.T) {
	// Reverse top-level fields and tree fields: JSON object order is not semantic.
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(vexFixture), &object); err != nil {
		t.Fatal(err)
	}
	var tree map[string]json.RawMessage
	if err := json.Unmarshal(object["product_tree"], &tree); err != nil {
		t.Fatal(err)
	}
	body := `{"vulnerabilities":` + string(object["vulnerabilities"]) + `,"product_tree":{"relationships":` + string(tree["relationships"]) + `,"branches":` + string(tree["branches"]) + `},"document":` + string(object["document"]) + `}`
	want, err := convertRedHatVEX(context.Background(), vexDecode(t, body))
	if err != nil {
		t.Fatal(err)
	}
	var got *Record
	err = parseRedHatVEX(context.Background(), vexArchive(t, body), 1<<20, 1<<20, func(r *Record) error { got = r; return nil }, nil)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("stream differs: got=%+v want=%+v err=%v", got, want, err)
	}
}

// Compare the reviewer's compact empty-branch shape with the old whole-document
// decode without building a large archive or requiring a multi-GB experiment.
func TestR17VEXDecodeAllocation(t *testing.T) {
	body := `{"product_tree":{"branches":[` + strings.Repeat(`{},`, 65535) + `{}]}}`
	allocated := func(fn func()) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	old := allocated(func() {
		var doc vexDocument
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
	})
	now := allocated(func() {
		doc, err := decodeRedHatVEX(context.Background(), strings.NewReader(body))
		if err != nil || len(doc.Tree.Branches) != 0 {
			t.Fatalf("retained empty branches: %v", err)
		}
	})
	t.Logf("input=%d bytes, whole decode=%d bytes allocated, streaming=%d bytes allocated", len(body), old, now)
	if now > 8<<20 || now >= old/2 {
		t.Fatalf("decoding allocation regression: old=%d now=%d", old, now)
	}
}

func TestR17VEXRemediationAllPriorities(t *testing.T) {
	all := []vexStatement{
		{Category: "none_available", Details: "Fix deferred", Products: []string{"affected"}},
		{Category: "no_fix_planned", Details: "Will not fix", Products: []string{"affected"}},
		{Category: "workaround", Details: "Apply mitigation", Products: []string{"affected"}},
		{Category: "vendor_fix", URL: "https://access.redhat.com/errata/RHSA-2026:1234", Products: []string{"affected"}},
	}
	for n, want := range []string{"fix-deferred", "will-not-fix", "workaround-only", "affected"} {
		for _, reverse := range []bool{false, true} {
			doc := vexDecode(t, vexFixture)
			rem := append([]vexStatement(nil), all[:n+1]...)
			if reverse {
				slices.Reverse(rem)
			}
			doc.Vulnerabilities[0].Remediations = rem
			r, err := convertRedHatVEX(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range r.Affected {
				if a.Package == "unfixed" && a.Database["redhat_status"] != want {
					t.Fatalf("n=%d reverse=%v want=%s got=%+v", n, reverse, want, a)
				}
			}
		}
	}
}

type vexCancelReader struct {
	io.ReadSeeker
	cancel context.CancelFunc
}

func (r *vexCancelReader) Read(p []byte) (int, error) {
	n, err := r.ReadSeeker.Read(p)
	r.cancel()
	return n, err
}

func TestR17VEXStreamingBoundsAndCancellation(t *testing.T) {
	for _, body := range []string{
		`{"product_tree":{"branches":[` + strings.Repeat(`{"branches":[`, 65) + `{} ` + strings.Repeat(`]}`, 65) + `]}}`,
		`{"vulnerabilities":[{},{}]}`,
		`{"document":{"title":"` + strings.Repeat("x", (64<<10)+1) + `"}}`,
	} {
		if _, err := decodeRedHatVEX(context.Background(), strings.NewReader(body)); err == nil {
			t.Fatal("accepted excessive structure/scalar")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := decodeRedHatVEX(ctx, &vexCancelReader{ReadSeeker: strings.NewReader(vexFixture), cancel: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestR17VEXDefaultDocumentLimit(t *testing.T) {
	// The production ceiling (256 MiB) is clamped in parseRedHatVEXExpanded;
	// a caller-supplied ceiling above it must not widen it. Building a
	// 256 MiB document is too heavy for the default run, so exercise the
	// clamp with the heavy-test switch and the caller ceiling otherwise.
	limit := int64(16 << 20)
	callerLimit := int64(limit)
	if os.Getenv("BSCAN_HEAVY_TESTS") == "1" {
		limit, callerLimit = vexMaxDocument, vexMaxDocument*4
	}
	// Extra whitespace is valid JSON and allocated only for this bound test.
	body := vexFixture + strings.Repeat(" ", int(limit)-len(vexFixture)+1)
	path := vexArchive(t, body)
	var log string
	emitted := 0
	err := parseRedHatVEX(context.Background(), path, uint64(callerLimit)*2, callerLimit, func(*Record) error { emitted++; return nil }, func(s string) { log = s })
	if err != nil || emitted != 0 || !strings.Contains(log, "skipped_oversized=1") {
		t.Fatalf("emitted=%d log=%s err=%v", emitted, log, err)
	}
}

func TestR17VEXCacheExpansionRetained(t *testing.T) {
	archive, err := os.ReadFile(vexArchive(t, vexFixture, strings.Repeat(" ", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	client := httpx.New(time.Second)
	requests := 0
	client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests > 1 {
			if req.Header.Get("If-None-Match") == "" {
				t.Error("valid cache forced a new download")
			}
			return &http.Response{StatusCode: 304, Header: http.Header{}, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(archive)), Header: http.Header{"Etag": {`"vex"`}}, Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
	})
	opts := Options{Client: client, MaxFeedBytes: 1 << 20, MaxFeedUncompressedBytes: 1 << 20, NoKeepRaw: true}
	feed := Feed{Source: SourceRedHatVEX, Key: "vex", File: "vex.tar.zst", URL: "https://example.org/vex.tar.zst", Parse: func(ctx context.Context, p string, _ int64, emit Emit, progress func(string)) error {
		return parseRedHatVEX(ctx, p, opts.maxFeedUncompressedBytes(), 16<<20, emit, progress)
	}}
	dir := t.TempDir()
	var previous map[string]SourceMeta
	// Tar includes both JSON entry sizes, headers, alignment and trailing blocks.
	want := uint64(512 + ((len(vexFixture)+511)/512)*512 + 512 + 4096 + 1024)
	for i := 0; i < 3; i++ {
		stage := t.TempDir()
		spool, err := newIngestionSpool(stage)
		if err != nil {
			t.Fatal(err)
		}
		m, err := updateFeed(context.Background(), dir, stage, feed, previous, opts, time.Now(), spool)
		if closeErr := spool.close(); err != nil || closeErr != nil {
			t.Fatalf("update %d: %v %v", i, err, closeErr)
		}
		var meta feedExpansionMeta
		if err := readJSON(filepath.Join(stage, "cache", SourceRedHatVEX, "vex.jsonl.gz.meta.json"), &meta); err != nil || meta.ExpandedBytes != want {
			t.Fatalf("update %d: meta=%+v want=%d err=%v", i, meta, want, err)
		}
		dir = stage
		previous = map[string]SourceMeta{SourceRedHatVEX + "\x00" + feed.URL: m}
		opts.MaxFeedUncompressedBytes = int64(want) // exact boundary still reuses cache
	}
}

func TestR17VEXRepeatedArraysAndShapes(t *testing.T) {
	for _, body := range []string{
		`{"product_tree":{"relationships":[` + strings.Repeat(`{},`, 50000) + `{}],"relationships":[` + strings.Repeat(`{},`, 50000) + `{}]}}`,
		`{"vulnerabilities":[{"product_status":{"known_affected":[{}]}}]}`,
		`{"product_tree":{"branches":{}}}`,
		`{"vulnerabilities":{}}`,
	} {
		if _, err := decodeRedHatVEX(context.Background(), strings.NewReader(body)); err == nil {
			t.Fatal("accepted excessive or malformed arrays")
		}
	}
}
