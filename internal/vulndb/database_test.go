package vulndb

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func fixtureZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for n, s := range files {
		w, e := z.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(s)); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func osvFixture(id, eco, name string) string {
	v := map[string]any{"id": id, "aliases": []string{"CVE-2025-1234"}, "affected": []any{map[string]any{"package": map[string]string{"ecosystem": eco, "name": name}, "ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "2.0"}}}}}}}
	b, _ := json.Marshal(v)
	return string(b)
}
func TestDatabaseUpdateLookupConditionalIntegrityArchive(t *testing.T) {
	var requests, notModified atomic.Int32
	var failing atomic.Bool
	fixtures := map[string][]byte{
		"/osv/npm/all.zip":             fixtureZip(t, map[string]string{"npm.json": osvFixture("GHSA-2345-abcd-6789", "npm", "@scope/name")}),
		"/osv/PyPI/all.zip":            fixtureZip(t, map[string]string{"pypi.json": osvFixture("PYSEC-2025-123", "PyPI", "Py_YAML")}),
		"/osv/Alpine/all.zip":          fixtureZip(t, map[string]string{"alpine.json": osvFixture("CVE-2025-1234", "Alpine:v3.20", "openssl")}),
		"/alpine/v3.20/main.json":      []byte(`{"packages":[{"pkg":{"name":"openssl","secfixes":{"3.1-r1":["CVE-2025-1234"],"0":["CVE-2025-9999"]}}}]}`),
		"/alpine/v3.20/community.json": []byte(`{"packages":[]}`),
		"/debian.json":                 []byte(`{"curl":{"CVE-2025-5555":{"releases":{"trixie":{"status":"resolved","fixed_version":"8.0-2"}}}}}`),
		"/ghsa.zip":                    fixtureZip(t, map[string]string{"repo/advisories/github-reviewed/2025/x/a.json": osvFixture("GHSA-abcd-2345-6789", "npm", "lodash"), "repo/advisories/unreviewed/x.json": osvFixture("GHSA-9999-abcd-1234", "npm", "ignored")}),
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if failing.Load() {
			http.Error(w, "temporary", 503)
			return
		}
		b, ok := fixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"fixture"`)
		if r.Header.Get("If-None-Match") == `"fixture"` {
			notModified.Add(1)
			w.WriteHeader(304)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	client := httpx.New(time.Minute)
	client.HTTP.Transport = srv.Client().Transport
	pub, priv, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Sources: []string{"osv", "alpine", "debian", "ghsa"}, Ecosystems: []string{"npm", "PyPI", "Alpine"}, AlpineReleases: []string{"v3.20"}, OSVBaseURL: srv.URL + "/osv", AlpineBaseURL: srv.URL + "/alpine", DebianURL: srv.URL + "/debian.json", GHSAURL: srv.URL + "/ghsa.zip", Client: client, PrivateKey: priv}
	dir := filepath.Join(t.TempDir(), "db")
	meta, err := Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Records != 5 {
		t.Fatalf("records=%d", meta.Records)
	}
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, q := range [][2]string{{"Debian:13", "curl"}, {"npm", "@scope/name"}, {"PyPI", "py.yaml"}, {"Alpine:v3.20", "openssl"}, {"npm", "lodash"}} {
		rs, err := st.Lookup(q[0], q[1])
		if err != nil || len(rs) != 1 {
			t.Fatalf("lookup %v: %+v, %v", q, rs, err)
		}
	}
	rs, err := st.Lookup("Alpine", "openssl")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs[0].Affected) != 2 || !strings.Contains(rs[0].Source, "alpine-secdb") {
		t.Fatalf("merge %+v", rs)
	}
	rs[0].Affected[0].Database = map[string]any{"modified": true}
	rs, err = st.Lookup("Alpine", "openssl")
	if err != nil || rs[0].Affected[0].Database["modified"] != nil {
		t.Fatal("lookup mutates cache", err)
	}
	if err = Verify(dir, pub); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err = Verify(dir, other); err == nil {
		t.Fatal("accepted wrong pinned key")
	}
	before, _ := os.ReadFile(filepath.Join(dir, "cache", "osv", "Alpine.jsonl.gz"))
	_, err = Update(context.Background(), dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if notModified.Load() != int32(len(fixtures)) {
		t.Fatalf("304 count %d", notModified.Load())
	}
	after, _ := os.ReadFile(filepath.Join(dir, "cache", "osv", "Alpine.jsonl.gz"))
	if !bytes.Equal(before, after) {
		t.Fatal("304 changed index")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "raw", "debian-tracker", "debian.json"))
	if !bytes.Equal(raw, fixtures["/debian.json"]) {
		t.Fatal("304 lost raw feed")
	}
	opts.NoKeepRaw = true
	for i := 0; i < 2; i++ {
		if _, err = Update(context.Background(), dir, opts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = os.Stat(filepath.Join(dir, "raw", "debian-tracker", "debian.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-keep-raw retained file: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "db.tar.gz")
	if err = Export(dir, archive); err != nil {
		t.Fatal(err)
	}
	imported := filepath.Join(t.TempDir(), "db")
	m, err := Import(archive, imported, pub)
	if err != nil || m.Records != meta.Records {
		t.Fatalf("import %+v %v", m, err)
	}
	is, err := Open(imported)
	if err != nil {
		t.Fatal(err)
	}
	irs, err := is.Lookup("Alpine", "openssl")
	if len(rs) == 1 && len(irs) == 1 {
		rs[0].LastSeenAt = irs[0].LastSeenAt
	}
	if err != nil || !reflect.DeepEqual(rs, irs) {
		t.Fatalf("roundtrip mismatch %v", err)
	}
	is.Close()
	manifest, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	failing.Store(true)
	attempted, err := Update(context.Background(), dir, opts)
	if err == nil || len(attempted.Sources) != len(fixtures) {
		t.Fatalf("failed update %v %+v", err, attempted)
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if !bytes.Equal(manifest, unchanged) {
		t.Fatal("failed update replaced database")
	}
	reqs := requests.Load()
	opts.Offline = true
	if _, err = Update(context.Background(), dir, opts); err == nil || requests.Load() != reqs {
		t.Fatal("offline made requests")
	}
	if err = os.WriteFile(filepath.Join(imported, SQLiteFileName), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(imported); err == nil || !strings.Contains(err.Error(), "database integrity check failed") {
		t.Fatalf("tamper accepted: %v", err)
	}
}
func TestFetchFeedPreservesRawOnFailureAnd304(t *testing.T) {
	var status atomic.Int32
	status.Store(304)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte("broken"))
	}))
	defer srv.Close()
	c := httpx.New(time.Minute)
	c.HTTP.Transport = srv.Client().Transport
	p := filepath.Join(t.TempDir(), "raw")
	if err := os.WriteFile(p, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int32{304, 500} {
		status.Store(code)
		_, err := fetchFeed(context.Background(), c, Feed{URL: srv.URL, MaxBytes: 100}, &SourceMeta{ETag: "x"}, p, false, time.Now())
		if code == 500 && err == nil {
			t.Fatal("missing error")
		}
		b, _ := os.ReadFile(p)
		if string(b) != "original" {
			t.Fatalf("status %d truncated raw", code)
		}
	}
}

func TestManifestAuthenticatesRawFeeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "raw", "osv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw", "osv", "npm.zip")
	if err := os.WriteFile(raw, []byte("original feed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, []byte("altered feed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir, nil); err == nil || !strings.Contains(err.Error(), "raw/osv/npm.zip: checksum mismatch") {
		t.Fatalf("raw feed tamper accepted: %v", err)
	}
	if err := os.WriteFile(raw, []byte("original feed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "raw", "osv", "extra.zip"), []byte("unlisted feed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir, nil); err == nil || !strings.Contains(err.Error(), "file missing from manifest: raw/osv/extra.zip") {
		t.Fatalf("unlisted raw feed accepted: %v", err)
	}
}
func TestImportRejectsUnsafeArchive(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "link"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "archive.gz")
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			h := &tar.Header{Name: name, Mode: 0644, Typeflag: tar.TypeReg}
			if name == "link" {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "/tmp"
			}
			if err = tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			tw.Close()
			gz.Close()
			f.Close()
			if _, err = Import(p, filepath.Join(t.TempDir(), "db"), nil); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

type cancelAfterChecks struct {
	context.Context
	remaining atomic.Int32
}

func (c *cancelAfterChecks) Err() error {
	if c.remaining.Add(-1) <= 0 {
		return context.Canceled
	}
	return nil
}

func TestImportContextCancellationPreservesDestination(t *testing.T) {
	root := t.TempDir()
	source := readerCatalog(t)
	rawDir := filepath.Join(source, "raw", "osv")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rawDir, "large.zip"), bytes.Repeat([]byte("archive payload"), 1<<18), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "manifest.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(source, Options{}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "import.tar.gz")
	if err := Export(source, archive); err != nil {
		t.Fatal(err)
	}
	destination := readerCatalog(t)
	before, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(20)
	if _, err = ImportContext(ctx, archive, destination, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-import cancellation returned %v", err)
	}
	after, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("canceled import replaced the installed database")
	}
	if err := Verify(destination, nil); err != nil {
		t.Fatalf("canceled import damaged destination: %v", err)
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(destination), filepath.Base(destination)+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("canceled import leaked staging directories: %v", stages)
	}
}

func TestCopyFileContextCancellationRemovesPartialFile(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.WriteFile(source, bytes.Repeat([]byte("copy payload"), 1<<18), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(3)
	if err := copyFileContext(ctx, source, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("copy cancellation returned %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination retained: %v", err)
	}
}

func TestUpdateCancellationDuringRetainedCacheCopy(t *testing.T) {
	zipped := fixtureZip(t, map[string]string{"advisory.json": osvFixture("GHSA-update-cancel", "npm", "fixture")})
	var notModified atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"cancel-fixture"`)
		if r.Header.Get("If-None-Match") == `"cancel-fixture"` {
			notModified.Store(true)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(zipped)
	}))
	defer server.Close()
	client := httpx.New(time.Minute)
	client.HTTP.Transport = server.Client().Transport
	opts := Options{Sources: []string{SourceOSV}, Ecosystems: []string{"npm"}, OSVBaseURL: server.URL, Client: client}
	destination := filepath.Join(t.TempDir(), "db")
	if _, err := Update(context.Background(), destination, opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelWhenStagedFileWritten{Context: context.Background(), destination: destination, rel: filepath.Join("cache", SourceOSV, "npm.jsonl.gz")}
	if _, err = Update(ctx, destination, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("update cancellation returned %v", err)
	}
	if !notModified.Load() {
		t.Fatal("conditional update did not exercise retained-cache copy")
	}
	after, err := os.ReadFile(filepath.Join(destination, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("canceled update replaced destination")
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(destination), filepath.Base(destination)+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("canceled update leaked staging directories: %v", stages)
	}
}

func TestUpdateCanceledAndLocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Update(ctx, filepath.Join(t.TempDir(), "db"), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "db")
	unlock, err := lockDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err = Update(context.Background(), dir, Options{}); err == nil {
		t.Fatal("concurrent writer accepted")
	}
}

func TestOpenKeepsVerifiedGenerationAcrossUpdates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	build := func(id string) {
		stage, err := os.MkdirTemp(filepath.Dir(dir), "stage-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(stage)
		m := Meta{SchemaVersion: SchemaVersion}
		r := &Record{ID: id, Affected: []Affected{{Ecosystem: "npm", Package: "x"}}}
		if err = buildIndexes(stage, map[string]*Record{id: r}, &m); err != nil {
			t.Fatal(err)
		}
		if err = writeJSON(filepath.Join(stage, "meta.json"), m); err != nil {
			t.Fatal(err)
		}
		if err = writeManifest(stage, Options{}); err != nil {
			t.Fatal(err)
		}
		if err = installDatabase(stage, dir); err != nil {
			t.Fatal(err)
		}
	}
	build("CVE-2025-1111")
	old, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	// Two generations remove db.prev as well; open descriptors still retain
	// the verified old inode until the reader finishes its first lazy lookup.
	build("CVE-2025-2222")
	build("CVE-2025-3333")
	got, err := old.Lookup("npm", "x")
	if err != nil || len(got) != 1 || got[0].ID != "CVE-2025-1111" {
		t.Fatalf("reader mixed generations: %+v %v", got, err)
	}
	current, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	got, err = current.Lookup("npm", "x")
	if err != nil || len(got) != 1 || got[0].ID != "CVE-2025-3333" {
		t.Fatalf("new reader: %+v %v", got, err)
	}
	old.Close()
	if _, err = old.Lookup("npm", "x"); err == nil {
		t.Fatal("closed lookup accepted")
	}
}

func TestRecordDecompressionLimits(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	for i := 0; i < 100; i++ {
		_, _ = gz.Write([]byte("{\"id\":\"CVE-2025-1234\",\"affected\":[]}\n"))
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readRecordsBounded(bytes.NewReader(compressed.Bytes()), func(*Record) error { return nil }, 100, 1024); err == nil {
		t.Fatal("expanded byte limit ignored")
	}
	if err := readRecordsBounded(bytes.NewReader(compressed.Bytes()), func(*Record) error { return nil }, 10000, 16); err == nil {
		t.Fatal("record size limit ignored")
	}
}

func TestOSVDatabaseMetadataSurvivesConversionAndStorage(t *testing.T) {
	var raw osvVuln
	input := `{"id":"GHSA-cpgg-pjqx-vqgp","database_specific":{"severity":"HIGH","cwe_ids":["CWE-79"]},"affected":[{"package":{"ecosystem":"npm","name":"x"}}]}`
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		t.Fatal(err)
	}
	r, ok := ConvertOSV(&raw, SourceGHSA)
	if !ok || r.Database["severity"] != "HIGH" {
		t.Fatalf("metadata lost: %+v", r)
	}
	Merge(r, &Record{ID: r.ID, Database: map[string]any{"severity": "LOW", "reviewed": true}})
	if r.Database["severity"] != "HIGH" || r.Database["reviewed"] != true {
		t.Fatalf("merge metadata: %+v", r.Database)
	}
	path := filepath.Join(t.TempDir(), "records.gz")
	if err := writeRecords(path, []*Record{r}); err != nil {
		t.Fatal(err)
	}
	if err := readRecords(path, func(got *Record) error {
		if !reflect.DeepEqual(got.Database, r.Database) {
			t.Errorf("stored metadata: %+v", got.Database)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
