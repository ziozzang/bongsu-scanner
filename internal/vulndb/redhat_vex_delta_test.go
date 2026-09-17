package vulndb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

func deltaDoc(id, at, pkg string) string {
	return fmt.Sprintf(`{"document":{"tracking":{"id":%q,"current_release_date":%q}},"product_tree":{"branches":[{"product":{"product_id":"rhel","product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:9"}}}],"relationships":[{"category":"default_component_of","full_product_name":{"product_id":"p"},"product_reference":%q,"relates_to_product_reference":"rhel"}]},"vulnerabilities":[{"cve":%q,"product_status":{"known_affected":["p"]}}]}`, id, at, pkg, id)
}
func deltaRow(id, at string) string {
	return fmt.Sprintf("\"2026/%s.json\",%q\n", strings.ToLower(id), at)
}

type deltaFixture struct {
	mu                           sync.Mutex
	archive                      []byte
	date, changes, deleted, etag string
	docs                         map[string]string
	requests, notModified        map[string]int
	server                       *httptest.Server
	client                       *httpx.Client
}

func newDeltaFixture(t *testing.T) *deltaFixture {
	t.Helper()
	f := &deltaFixture{date: "2026-09-13", etag: "list1", docs: map[string]string{}, requests: map[string]int{}, notModified: map[string]int{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests[r.URL.Path]++
		body, tag := "", ""
		switch {
		case r.URL.Path == "/archive_latest.txt":
			body = "csaf_vex_" + f.date + ".tar.zst"
		case strings.HasSuffix(r.URL.Path, ".tar.zst"):
			body = string(f.archive)
			tag = f.date
		case r.URL.Path == "/changes.csv":
			body = f.changes
			tag = f.etag
		case r.URL.Path == "/deletions.csv":
			body = f.deleted
		default:
			var ok bool
			body, ok = f.docs[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
		}
		if tag != "" {
			w.Header().Set("ETag", tag)
			if r.Header.Get("If-None-Match") == tag {
				f.notModified[r.URL.Path]++
				w.WriteHeader(304)
				return
			}
		}
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(f.server.Close)
	f.client = httpx.New(5 * time.Second)
	f.client.HTTP.Transport = f.server.Client().Transport
	return f
}
func (f *deltaFixture) setArchive(t *testing.T, docs ...string) {
	t.Helper()
	b, e := os.ReadFile(vexArchive(t, docs...))
	if e != nil {
		t.Fatal(e)
	}
	f.archive = b
}
func (f *deltaFixture) options(t *testing.T) Options {
	t.Helper()
	old := registry[SourceRedHatVEX]
	registry[SourceRedHatVEX] = func() Source { return &redHatVEXSource{baseURL: f.server.URL} }
	t.Cleanup(func() { registry[SourceRedHatVEX] = old })
	return Options{Sources: []string{SourceRedHatVEX}, Client: f.client, NoKeepRaw: true}
}
func deltaMeta(t *testing.T, m Meta) SourceMeta {
	t.Helper()
	for _, s := range m.Sources {
		if !s.ArchiveDate.IsZero() {
			return s
		}
	}
	t.Fatal("missing delta metadata")
	return SourceMeta{}
}
func deltaRecords(t *testing.T, dir string) map[string]Record {
	t.Helper()
	st, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	out := map[string]Record{}
	if e := visitStoreRecords(context.Background(), st, func(r *Record) error { out[r.ID] = *r; return nil }); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestVEXDeltaUpdates(t *testing.T) {
	f := newDeltaFixture(t)
	a, b, c := "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"
	f.setArchive(t, deltaDoc(a, "2026-09-13T00:00:00Z", "old"), deltaDoc(b, "2026-09-13T00:00:00Z", "deleted"))
	f.changes = deltaRow(a, "2026-09-14T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(a, "2026-09-14T00:00:00Z", "replacement")
	f.deleted = deltaRow(b, "2026-09-15T00:00:00Z")
	opts := f.options(t)
	var logs []string
	opts.Progress = func(s string) { logs = append(logs, s) }
	dir := filepath.Join(t.TempDir(), "db")
	first, e := Update(context.Background(), dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	records := deltaRecords(t, dir)
	if len(records[a].Affected) != 1 || records[a].Affected[0].Package != "replacement" || records[b].Withdrawn == "" || len(records[b].Affected) != 0 {
		t.Fatalf("replacement/deletion: %+v", records)
	}
	m := deltaMeta(t, first)
	if m.DeltaDocuments != 1 || m.DeltaDeleted != 1 || m.DataThrough.Format(time.DateOnly) != "2026-09-15" {
		t.Fatalf("first meta: %+v", m)
	}
	// A longer list with a timestamp tied to an already applied deletion.
	f.mu.Lock()
	f.etag = "list2"
	f.changes = deltaRow(c, "2026-09-15T00:00:00Z") + f.changes
	f.docs["/2026/cve-2026-1003.json"] = deltaDoc(c, "2026-09-15T00:00:00Z", "new")
	f.mu.Unlock()
	second, e := Update(context.Background(), dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	m = deltaMeta(t, second)
	if m.DeltaDocuments != 2 || m.DeltaFetched != 1 {
		t.Fatalf("second: %+v", m)
	}
	if r := deltaRecords(t, dir); len(r[a].Affected) != 1 || r[a].Affected[0].Package != "replacement" || r[b].Withdrawn == "" || len(r[c].Affected) != 1 {
		t.Fatalf("cache overlay: %+v", r)
	}
	third, e := Update(context.Background(), dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	if m = deltaMeta(t, third); m.DeltaFetched != 0 || m.DeltaDocuments != 2 {
		t.Fatalf("304: %+v", m)
	}
	f.mu.Lock()
	if f.requests["/2026/cve-2026-1001.json"] != 1 || f.requests["/2026/cve-2026-1003.json"] != 1 || f.notModified["/csaf_vex_2026-09-13.tar.zst"] != 2 || f.notModified["/changes.csv"] != 1 {
		t.Errorf("requests=%v 304=%v", f.requests, f.notModified)
	}
	f.mu.Unlock()
	if text := strings.Join(logs, "\n"); !strings.Contains(text, "vex: not modified (304)") || !strings.Contains(text, "changes.csv: not modified (304)") {
		t.Fatalf("missing conditional status: %s", text)
	}
	// New archive discards the old delta cache even if changes.csv returns 304.
	f.mu.Lock()
	f.date = "2026-09-17"
	f.setArchive(t, deltaDoc(a, "2026-09-17T00:00:00Z", "fresh"))
	f.mu.Unlock()
	fourth, e := Update(context.Background(), dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	if m = deltaMeta(t, fourth); m.DeltaDocuments != 0 || m.DeltaFetched != 0 || !m.DeltaThrough.IsZero() {
		t.Fatalf("rollover: %+v", m)
	}
	if records = deltaRecords(t, dir); len(records) != 1 || records[a].Affected[0].Package != "fresh" {
		t.Fatalf("stale overlay survived archive: %+v", records)
	}
	if _, e := os.Stat(filepath.Join(dir, "raw", SourceRedHatVEX, "vex.tar.zst")); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("raw retained: %v", e)
	}
}

func TestVEXDeltaIndependentDeletion(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1111"
	f.setArchive(t, deltaDoc(id, "2026-09-13T00:00:00Z", "old"))
	opts := f.options(t)
	dir := filepath.Join(t.TempDir(), "db")
	if _, e := Update(context.Background(), dir, opts); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.deleted = deltaRow(id, "2026-09-14T00:00:00Z")
	f.mu.Unlock()
	if _, e := Update(context.Background(), dir, opts); e != nil {
		t.Fatal(e)
	}
	if r := deltaRecords(t, dir)[id]; r.Withdrawn == "" || len(r.Affected) != 0 {
		t.Fatalf("deletion with list 304: %+v", r)
	}
}

func runDeltaFeed(t *testing.T, f *deltaFixture, d *vexDeltaFeed, previous map[string]SourceMeta, dir string) (SourceMeta, string, error) {
	t.Helper()
	stage := t.TempDir()
	sp, e := newIngestionSpool(stage)
	if e != nil {
		t.Fatal(e)
	}
	d.baseURL = f.server.URL + "/"
	d.client = f.client
	d.archiveDate = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	feed := Feed{Source: SourceRedHatVEX, Key: "vex-changes", URL: d.baseURL + "changes.csv", File: "changes.csv", MaxBytes: vexListMaxBytes, Parse: d.parse, vexDelta: d}
	m, e := updateFeed(context.Background(), dir, stage, feed, previous, Options{Client: f.client, NoKeepRaw: true}, time.Now(), sp)
	if ce := sp.close(); ce != nil {
		t.Fatal(ce)
	}
	return m, stage, e
}
func TestVEXDeltaBoundsAndResume(t *testing.T) {
	f := newDeltaFixture(t)
	f.changes = "\"../cve-2026-1000.json\",\"2026-09-14T00:00:00Z\"\n" + "\"2026/%2e%2e/cve-2026-1000.json\",\"2026-09-14T00:00:00Z\"\n" + "broken\n" + deltaRow("CVE-2026-1001", "bad-date")
	for i := 1002; i < 1008; i++ {
		id := fmt.Sprintf("CVE-2026-%d", i)
		f.changes += deltaRow(id, "2026-09-14T00:00:00Z")
		f.docs[fmt.Sprintf("/2026/cve-2026-%d.json", i)] = deltaDoc(id, "2026-09-14T00:00:00Z", "demo")
	}
	f.docs["/2026/cve-2026-1002.json"] = "{"
	f.docs["/2026/cve-2026-1003.json"] = strings.Repeat("x", 2049)
	d := &vexDeltaFeed{budget: 1 << 20, maxDocuments: 3, maxDocument: 2048}
	m, dir, e := runDeltaFeed(t, f, d, nil, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if m.DeltaMalformed != 5 || m.DeltaOversized != 1 || m.DeltaFetched != 1 || m.DeltaRemaining != 3 {
		t.Fatalf("bounds: %+v", m)
	}
	prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
	d.maxDocuments = 20
	m, _, e = runDeltaFeed(t, f, d, prev, dir)
	if e != nil || m.DeltaFetched != 3 || m.DeltaRemaining != 0 || m.DeltaDocuments != 4 {
		t.Fatalf("resume: %+v %v", m, e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests["/2026/cve-2026-1002.json"] != 1 || f.requests["/2026/cve-2026-1003.json"] != 1 {
		t.Fatal("skipped docs retried", f.requests)
	}
}
func TestVEXDeltaByteBudget(t *testing.T) {
	f := newDeltaFixture(t)
	f.changes = deltaRow("CVE-2026-1001", "2026-09-14T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc("CVE-2026-1001", "2026-09-14T00:00:00Z", "demo")
	d := &vexDeltaFeed{budget: 10, maxDocuments: 20, maxDocument: 2048}
	m, dir, e := runDeltaFeed(t, f, d, nil, t.TempDir())
	if e != nil || m.DeltaFetched != 0 || m.DeltaRemaining != 1 || m.DeltaBytes > 10 || !m.DeltaThrough.IsZero() {
		t.Fatalf("budget: %+v %v", m, e)
	}
	d.budget = 2048
	prev := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
	m, _, e = runDeltaFeed(t, f, d, prev, dir)
	if e != nil || m.DeltaFetched != 1 || m.DeltaRemaining != 0 {
		t.Fatalf("budget resume: %+v %v", m, e)
	}
}
func TestVEXMergeLatestAndOtherSources(t *testing.T) {
	old := Record{ID: "CVE-2026-1001", Source: SourceRedHatVEX, Modified: "2026-09-13T00:00:00Z", Affected: []Affected{{Package: "old"}}}
	newRecord := Record{ID: old.ID, Source: SourceRedHatVEX, Modified: "2026-09-14T01:00:00+01:00", Affected: []Affected{{Package: "new"}}}
	for _, reverse := range []bool{false, true} {
		a, b := old, newRecord
		if reverse {
			a, b = b, a
		}
		Merge(&a, &b)
		if !reflect.DeepEqual(a, newRecord) {
			t.Fatalf("latest: %+v", a)
		}
	}
	old.Source, newRecord.Source = SourceOSV, SourceDebian
	Merge(&old, &newRecord)
	if len(old.Affected) != 2 {
		t.Fatal("union changed")
	}
}
func TestVEXDeltaStatus(t *testing.T) {
	m := SourceMeta{Name: SourceRedHatVEX, ArchiveDate: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC), DeltaThrough: time.Date(2026, 9, 17, 14, 18, 45, 0, time.UTC), DeltaDocuments: 2111}
	if got := m.VEXStatus(); !strings.Contains(got, "archive 2026-09-13, deltas through 2026-09-17T14:18Z (2,111 documents)") {
		t.Fatal(got)
	}
	if (SourceMeta{}).VEXStatus() != "" {
		t.Fatal("old catalog status changed")
	}
}

func TestVEXDeltaCancellationAndConcurrency(t *testing.T) {
	ready := make(chan struct{}, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ready <- struct{}{}; <-r.Context().Done() }))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	d := &vexDeltaFeed{baseURL: server.URL + "/", client: client, maxDocument: 2048}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 4)
	stage := t.TempDir()
	budget := &vexDeltaBudget{left: 1 << 20}
	for i := 1000; i < 1004; i++ {
		go func() {
			done <- d.document(ctx, stage, vexDeltaEntry{Path: fmt.Sprintf("2026/cve-2026-%d.json", i)}, budget).err
		}()
	}
	for range 4 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("four requests did not run concurrently")
		}
	}
	cancel()
	for range 4 {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("spool leaked: %v %v", entries, err)
	}
}

func TestVEXDeltaRetryHTTPSAndFiltered(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	id := "CVE-2026-1001"
	body := strings.ReplaceAll(deltaDoc(id, "2026-09-14T00:00:00Z", "demo"), "cpe:/o:redhat:enterprise_linux:9", "cpe:/o:other:thing:9")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()
	client := httpx.New(time.Second)
	client.HTTP.Transport = server.Client().Transport
	d := &vexDeltaFeed{baseURL: server.URL + "/", client: client, maxDocument: 2048}
	entry := vexDeltaEntry{Path: "2026/cve-2026-1001.json"}
	r := d.document(context.Background(), t.TempDir(), entry, &vexDeltaBudget{left: 1 << 20})
	if r.err != nil || r.record == nil || len(r.record.Affected) != 0 || r.record.ID != id {
		t.Fatalf("filtered replacement: %+v", r)
	}
	mu.Lock()
	if calls != 2 {
		t.Errorf("retries=%d", calls)
	}
	mu.Unlock()
	d.baseURL = "http://example.invalid/"
	if r = d.document(context.Background(), t.TempDir(), entry, &vexDeltaBudget{left: 2048}); !errors.Is(r.err, httpx.ErrInsecureURL) {
		t.Fatalf("HTTP accepted: %v", r.err)
	}
}

func TestVEXDeltaOversizedLists(t *testing.T) {
	for _, target := range []string{"/changes.csv", "/deletions.csv"} {
		t.Run(target, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == target {
					w.Header().Set("Content-Length", fmt.Sprint(vexListMaxBytes+1))
					return
				}
			}))
			defer server.Close()
			client := httpx.New(time.Second)
			client.HTTP.Transport = server.Client().Transport
			f := &deltaFixture{server: server, client: client}
			d := &vexDeltaFeed{budget: 1 << 20, maxDocuments: 20, maxDocument: 2048}
			if _, _, err := runDeltaFeed(t, f, d, nil, t.TempDir()); !errors.Is(err, httpx.ErrTooLarge) {
				t.Fatalf("list cap: %v", err)
			}
		})
	}
}

type deltaOtherSource struct{ url string }

func (s deltaOtherSource) Name() string { return SourceDebian }
func (s deltaOtherSource) Feeds(*Options) ([]Feed, error) {
	return []Feed{{Source: SourceDebian, Key: "other", File: "other.json", URL: s.url, Parse: func(_ context.Context, _ string, _ int64, emit Emit, _ func(string)) error {
		return emit(&Record{ID: "CVE-2026-1001", Source: SourceDebian, Affected: []Affected{{Ecosystem: "Debian:12", Package: "debian"}}})
	}}}, nil
}
func TestVEXDeltaBeforeCrossSourceUnion(t *testing.T) {
	f := newDeltaFixture(t)
	id := "CVE-2026-1001"
	f.setArchive(t, deltaDoc(id, "2026-09-13T00:00:00Z", "stale"))
	f.changes = deltaRow(id, "2026-09-14T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(id, "2026-09-14T00:00:00Z", "current")
	f.docs["/other.json"] = "{}"
	opts := f.options(t)
	old := registry[SourceDebian]
	registry[SourceDebian] = func() Source { return deltaOtherSource{f.server.URL + "/other.json"} }
	defer func() { registry[SourceDebian] = old }()
	for _, sources := range [][]string{{SourceDebian, SourceRedHatVEX}, {SourceRedHatVEX, SourceDebian}} {
		opts.Sources = sources
		dir := filepath.Join(t.TempDir(), "db")
		if _, err := Update(context.Background(), dir, opts); err != nil {
			t.Fatal(err)
		}
		r := deltaRecords(t, dir)[id]
		if len(r.Affected) != 2 {
			t.Fatalf("union: %+v", r)
		}
		for _, a := range r.Affected {
			if a.Package == "stale" {
				t.Fatal("stale VEX survived union")
			}
		}
	}
}

func TestVEXDeltaParserCancellation(t *testing.T) {
	started := make(chan struct{}, 8)
	var mu sync.Mutex
	active, peak := 0, 0
	var list string
	for i := 1000; i < 1008; i++ {
		list += deltaRow(fmt.Sprintf("CVE-2026-%d", i), "2026-09-14T00:00:00Z")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/changes.csv":
			_, _ = fmt.Fprint(w, list)
			return
		case "/deletions.csv":
			return
		}
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		started <- struct{}{}
		<-r.Context().Done()
		mu.Lock()
		active--
		mu.Unlock()
	}))
	defer server.Close()
	client := httpx.New(10 * time.Second)
	client.HTTP.Transport = server.Client().Transport
	d := &vexDeltaFeed{baseURL: server.URL + "/", archiveDate: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC), client: client, budget: 1 << 20, maxDocuments: 20, maxDocument: 2048}
	stage := t.TempDir()
	dir := t.TempDir()
	sp, err := newIngestionSpool(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	feed := Feed{Source: SourceRedHatVEX, Key: "vex-changes", URL: d.baseURL + "changes.csv", File: "changes.csv", MaxBytes: vexListMaxBytes, Parse: d.parse, vexDelta: d}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := updateFeed(ctx, dir, stage, feed, nil, Options{Client: client}, time.Now(), sp)
		done <- err
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("parser did not start four workers")
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("parser cancellation: %v", err)
	}
	mu.Lock()
	if peak != 4 {
		t.Errorf("peak workers=%d", peak)
	}
	mu.Unlock()
	files, err := filepath.Glob(filepath.Join(stage, "cache", SourceRedHatVEX, ".vex-delta-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("document spools leaked: %v %v", files, err)
	}
}
func TestVEXIndexCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	client := httpx.New(10 * time.Second)
	client.HTTP.Transport = server.Client().Transport
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (redHatVEXSource{baseURL: server.URL, ctx: ctx}).Feeds(&Options{Client: client})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("index cancellation: %v", err)
	}
}

func TestVEXDeltaFeedDefaultsAndCheckpoint(t *testing.T) {
	f := newDeltaFixture(t)
	feeds, err := (redHatVEXSource{baseURL: f.server.URL}).Feeds(&Options{Client: f.client})
	if err != nil || len(feeds) != 2 {
		t.Fatalf("feeds: %v %v", feeds, err)
	}
	d := feeds[1].vexDelta
	if feeds[1].MaxBytes != 16<<20 || d.budget != 2<<30 || d.maxDocuments != 20_000 || d.maxDocument != vexMaxDocument {
		t.Fatalf("delta bounds: %+v", d)
	}
	id := "CVE-2026-1001"
	f.changes = deltaRow(id, "2026-09-14T00:00:00Z")
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(id, "2026-09-14T00:00:00Z", "first")
	m, dir, err := runDeltaFeed(t, f, d, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A later row for the same CVE refreshes it; cached versions are compacted.
	f.mu.Lock()
	f.changes = deltaRow(id, "2026-09-15T00:00:00Z")
	f.etag = "list2"
	f.docs["/2026/cve-2026-1001.json"] = deltaDoc(id, "2026-09-15T00:00:00Z", "second")
	f.mu.Unlock()
	previous := map[string]SourceMeta{SourceRedHatVEX + "\x00" + f.server.URL + "/changes.csv": m}
	m, dir, err = runDeltaFeed(t, f, d, previous, dir)
	if err != nil || m.Records != 1 || m.DeltaFetched != 1 || m.DeltaDocuments != 2 {
		t.Fatalf("checkpoint: %+v %v", m, err)
	}
	err = readFeedCache(filepath.Join(dir, "cache", SourceRedHatVEX, "vex-changes.jsonl.gz"), 1<<20, func(r *Record) error {
		if len(r.Affected) != 1 || r.Affected[0].Package != "second" {
			t.Fatalf("old delta retained: %+v", r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
