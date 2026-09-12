package vulndb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

// Trigger the replacement at the verification boundary, without a timing race
// or a production test hook. This also exercises the original vulnerable read.
type replaceAfterVerification struct {
	context.Context
	replace func()
}

func (c *replaceAfterVerification) Err() error {
	pc, _, _, _ := runtime.Caller(1)
	if fn := runtime.FuncForPC(pc); fn != nil && strings.HasSuffix(fn.Name(), ".verifyWithDigestsContext") && c.replace != nil {
		replace := c.replace
		c.replace = nil
		replace()
	}
	return nil
}

func TestReviewMetadataReplacementAfterVerification(t *testing.T) {
	dir := readerCatalog(t)
	ctx := &replaceAfterVerification{Context: context.Background(), replace: func() {
		if err := writeJSON(filepath.Join(dir, "meta.json"), Meta{SchemaVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}}
	st, err := OpenVerifiedContext(ctx, dir, nil)
	if err == nil {
		st.Close()
		t.Fatal("accepted replaced metadata and silently empty ecosystems")
	}
	if !strings.Contains(err.Error(), "changed after verification") {
		t.Fatal(err)
	}
	if ctx.replace != nil {
		t.Fatal("verification-boundary replacement did not run")
	}
}

func TestReviewLegacyIndexIsolation(t *testing.T) {
	for _, name := range []string{"names.json", "records.jsonl.gz"} {
		for _, duringOpen := range []bool{false, true} {
			t.Run(name+map[bool]string{true: "-during-open", false: "-after-open"}[duringOpen], func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "db")
				legacySQLiteFixture(t, dir, nil)
				path := filepath.Join(dir, "index", safeName("PyPI"), name)
				mutate := func() {
					var err error
					if name == "names.json" {
						err = os.WriteFile(path, []byte("{}"), 0600)
					} else {
						err = writeRecords(path, nil)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				var ctx context.Context = context.Background()
				if duringOpen {
					ctx = &replaceAfterVerification{Context: ctx, replace: mutate}
				}
				st, err := OpenVerifiedContext(ctx, dir, nil)
				if duringOpen {
					if err == nil {
						st.Close()
						t.Fatal("accepted changed legacy index")
					}
					if !strings.Contains(err.Error(), "changed after verification") {
						t.Fatal(err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				mutate()
				records, err := st.Lookup("PyPI", "py.yaml")
				if err != nil || len(records) != 1 {
					t.Fatalf("isolated lookup: %+v %v", records, err)
				}
				records, err = LookupID(st, "CVE-2026-7777")
				if err != nil || len(records) != 1 {
					t.Fatalf("isolated ID lookup: %+v %v", records, err)
				}
			})
		}
	}
}

func TestReviewSignatureSizeLimit(t *testing.T) {
	for _, size := range []int{64 << 10, (64 << 10) + 1} {
		dir := readerCatalog(t)
		pub, priv, err := sign.Generate()
		if err != nil {
			t.Fatal(err)
		}
		digest, err := sign.FileDigest(filepath.Join(dir, "manifest.sha256"))
		if err != nil {
			t.Fatal(err)
		}
		rec, err := sign.Create(digest, "manifest.sha256", "", priv, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, bytes.Repeat([]byte(" "), size-len(data))...)
		if err = os.WriteFile(filepath.Join(dir, "manifest.sha256.sig"), data, 0600); err != nil {
			t.Fatal(err)
		}
		err = Verify(dir, pub)
		if size == 64<<10 && err != nil {
			t.Fatalf("boundary signature rejected: %v", err)
		}
		if size > 64<<10 && (err == nil || !strings.Contains(err.Error(), "signature exceeds 64 KiB")) {
			t.Fatalf("oversized valid signature: %v", err)
		}
	}
}

func TestReviewOpenRecoversInterruptedInstall(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		dir := readerCatalog(t)
		var pub ed25519.PublicKey
		if pinned {
			var priv ed25519.PrivateKey
			var err error
			pub, priv, err = sign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(filepath.Join(dir, "manifest.sha256")); err != nil {
				t.Fatal(err)
			}
			if err = writeManifest(dir, Options{PrivateKey: priv}); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Rename(dir, dir+".prev"); err != nil {
			t.Fatal(err)
		}
		var st Store
		var err error
		if pinned {
			st, err = OpenVerified(dir, pub)
		} else {
			st, err = Open(dir)
		}
		if err != nil {
			t.Fatalf("recover pinned=%v: %v", pinned, err)
		}
		records, err := st.Lookup("npm", "example")
		st.Close()
		if err != nil || len(records) != 1 {
			t.Fatalf("recovered lookup: %+v %v", records, err)
		}
		if _, err = os.Stat(dir + ".prev"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("backup not restored", err)
		}
	}
}

func TestReviewArchiveExpansionCountsExtendedHeaders(t *testing.T) {
	for _, format := range []tar.Format{tar.FormatPAX, tar.FormatGNU} {
		var payload bytes.Buffer
		gz := gzip.NewWriter(&payload)
		tw := tar.NewWriter(gz)
		h := &tar.Header{Name: strings.Repeat("x", 200), Typeflag: tar.TypeReg, Mode: 0600, Format: format}
		if format == tar.FormatPAX {
			h.PAXRecords = map[string]string{"comment": strings.Repeat("p", 8192)}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(t.TempDir(), "db.tar.gz")
		if err := os.WriteFile(archive, payload.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "db")
		_, err := importContextLimit(context.Background(), archive, dir, nil, 1024)
		if err == nil || !strings.Contains(err.Error(), "expanded database archive exceeds 1024 bytes (including headers)") {
			t.Fatalf("%v: %v", format, err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("oversized archive installed")
		}
		stages, _ := filepath.Glob(dir + ".tmp-*")
		if len(stages) != 0 {
			t.Fatalf("leaked stages: %v", stages)
		}
	}
}

func TestReviewSQLiteCompressionFixtureSize(t *testing.T) {
	legacyDir := filepath.Join(t.TempDir(), "legacy")
	legacySQLiteFixture(t, legacyDir, nil)
	legacy, err := Open(legacyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	records, err := legacy.Lookup("PyPI", "py.yaml")
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	dir := t.TempDir()
	meta := Meta{}
	if err = buildSQLite(context.Background(), dir, map[string]*Record{records[0].ID: &records[0]}, &meta); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, SQLiteFileName)
	db, err := sql.Open("sqlite", sqliteURI(path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var data []byte
	var storage string
	if err = db.QueryRow("SELECT json,typeof(json) FROM records").Scan(&data, &storage); err != nil {
		t.Fatal(err)
	}
	if storage != "blob" {
		t.Fatalf("record JSON is %s, want compressed BLOB", storage)
	}
	var decoded Record
	if err = decodeSQLiteRecord(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, records[0]) {
		t.Fatal("compressed record changed")
	}
	raw, err := json.Marshal(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= len(raw) {
		t.Fatalf("fixture did not compress: %d >= %d", len(data), len(raw))
	}
	if err = writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err = writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Lookup("PyPI", "py.yaml")
	if err != nil || !reflect.DeepEqual(got, records) {
		t.Fatal(got, err)
	}
	got, err = LookupID(st, "GHSA-cpgg-pjqx-vqgp")
	st.Close()
	if err != nil || !reflect.DeepEqual(got, records) {
		t.Fatal(got, err)
	}
	compressed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the former uncompressed payload with the identical normalized
	// tables and fixture, then VACUUM to compare physical catalog size fairly.
	if _, err = db.Exec("UPDATE records SET json=?", string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	plain, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("existing legacySQLiteFixture: records.json %d -> %d bytes; SQLite file %d -> %d bytes", len(raw), len(data), plain.Size(), compressed.Size())
}

func TestReviewSQLiteRejectsOldEncodingAndCorruptCompression(t *testing.T) {
	dir := readerCatalog(t)
	alterReaderCatalog(t, dir, "PRAGMA user_version=2; DELETE FROM metadata WHERE key='record_encoding'")
	st, err := Open(dir)
	if err == nil {
		st.Close()
		t.Fatal("old SQLite format accepted")
	}
	if !strings.Contains(err.Error(), "run bscan db update") {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"id":"CVE-2025-1234"}`), bytes.Repeat([]byte(" "), 4096)} {
		data, err := compressSQLiteJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		var record Record
		if err = decodeSQLiteRecordBounded(data, &record, 1024); len(raw) > 1024 && err == nil {
			t.Fatal("compression bomb accepted")
		}
		if len(raw) < 1024 && err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 0xff
		if err = decodeSQLiteRecord(data, &record); err == nil {
			t.Fatal("corrupt zlib checksum accepted")
		}
	}
}

func TestReviewSkipIsolationIsExplicitAndStillVerifies(t *testing.T) {
	dir := readerCatalog(t)
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{SkipIsolation: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.(*sqliteStore).snapshot != "" {
		t.Fatal("explicit opt-out still copied catalog")
	}
	records, err := st.Lookup("npm", "example")
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, SQLiteFileName)); err != nil {
		t.Fatal("close removed source", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, SQLiteFileName), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(f, "tamper")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithOptionsContext(context.Background(), dir, Options{SkipIsolation: true})
	if err == nil {
		st.Close()
		t.Fatal("opt-out skipped integrity verification")
	}
}

func TestReviewSQLiteCopyFallbackUsesSiblingTemp(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, SQLiteFileName)
	if err := os.WriteFile(dst, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	want := []byte(strings.Repeat("SQLite copy payload ", 4096))
	reader := &inspectCopyTempReader{t: t, dir: dir, dst: dst, reader: bytes.NewReader(want)}
	if err := copySQLiteFileContext(context.Background(), reader, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("copy mismatch", err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, ".sqlite-copy-*"))
	if len(paths) != 0 {
		t.Fatal("copy temp leaked", paths)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = copySQLiteFileContext(ctx, bytes.NewReader([]byte("replacement")), dst); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	got, err = os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("canceled copy replaced destination", err)
	}
	paths, _ = filepath.Glob(filepath.Join(dir, ".sqlite-copy-*"))
	if len(paths) != 0 {
		t.Fatal("canceled copy temp leaked", paths)
	}
}

type inspectCopyTempReader struct {
	t        *testing.T
	dir, dst string
	reader   io.Reader
}

func (r *inspectCopyTempReader) Read(p []byte) (int, error) {
	r.t.Helper()
	paths, err := filepath.Glob(filepath.Join(r.dir, ".sqlite-copy-*"))
	if err != nil || len(paths) != 1 {
		r.t.Fatalf("copy did not use sibling temp: %v %v", paths, err)
	}
	got, err := os.ReadFile(r.dst)
	if err != nil || string(got) != "previous" {
		r.t.Fatal("destination published before copy completed", err)
	}
	return r.reader.Read(p)
}
