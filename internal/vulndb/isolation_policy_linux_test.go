//go:build linux

package vulndb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIsolationAutoWithoutReflinkHoldsWriterLock(t *testing.T) {
	dir := readerCatalog(t)
	src, err := os.Open(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.CreateTemp(filepath.Dir(dir), "clone-probe")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if cloneSQLiteFile(dst, src) == nil {
		t.Skip("fixture filesystem supports reflink")
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.(*sqliteStore).snapshot != "" {
		t.Error("auto copied catalog without reflink")
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatal("second shared reader:", err)
	}
	defer second.Close()
	result := make(chan error, 1)
	go func() {
		unlock, err := lockDatabase(dir)
		if err == nil {
			unlock()
		}
		result <- err
	}()
	if err := <-result; err == nil {
		t.Error("exclusive writer lock acquired while readers open")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockDatabase(dir); err == nil {
		unlock()
		t.Error("second reader lost its lock")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDatabase(dir)
	if err != nil {
		t.Fatal("reader lock leaked:", err)
	}
	unlock()
}

func TestIsolationModes(t *testing.T) {
	for _, mode := range []string{"auto", "copy", "none", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			dir := readerCatalog(t)
			st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: mode})
			if mode == "invalid" {
				if err == nil {
					st.Close()
					t.Fatal("invalid isolation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if mode == "none" && st.(*sqliteStore).snapshot != "" {
				t.Error("none created a snapshot")
			}
			if mode == "copy" {
				if st.(*sqliteStore).snapshot == "" {
					t.Fatal("copy did not isolate")
				}
				if err := os.WriteFile(filepath.Join(dir, SQLiteFileName), []byte("damaged"), 0600); err != nil {
					t.Fatal(err)
				}
				records, err := st.Lookup("npm", "example")
				if err != nil || len(records) != 1 {
					t.Fatal("copy changed with source", records, err)
				}
			}
		})
	}
}

func TestReaderLegacyCleanupAge(t *testing.T) {
	parent := t.TempDir()
	for _, tc := range []struct {
		name   string
		age    time.Duration
		remove bool
	}{
		{"recent", 23 * time.Hour, false}, {"old", 25 * time.Hour, true}, {"future", -time.Hour, false},
	} {
		path := filepath.Join(parent, ".bscan-db-reader-"+tc.name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Add(-tc.age)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := removeStaleReaderSnapshots(parent); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) != tc.remove {
			t.Errorf("%s: removed=%v, want %v", tc.name, err, tc.remove)
		}
	}
}

// Each hash calls Err directly at entry and exit. Count only those boundaries,
// excluding checks made by the context-aware stream used inside the hash.
type hashCountingContext struct {
	context.Context
	calls       int
	readerCalls int
}

func (c *hashCountingContext) Err() error {
	pc, _, _, _ := runtime.Caller(1)
	if fn := runtime.FuncForPC(pc); fn != nil && strings.HasSuffix(fn.Name(), ".hashFileContext") {
		c.calls++
	}
	if fn := runtime.FuncForPC(pc); fn != nil && strings.HasSuffix(fn.Name(), ".hashReaderContext") {
		c.readerCalls++ // One exit boundary per completed descriptor or path hash.
	}
	return c.Context.Err()
}

func TestIsolationHashesSourceOnceAndRehashesOnlyCopy(t *testing.T) {
	for _, mode := range []string{"auto", "copy", "none"} {
		t.Run(mode, func(t *testing.T) {
			dir := readerCatalog(t)
			ctx := &hashCountingContext{Context: context.Background()}
			st, err := OpenWithOptionsContext(ctx, dir, Options{Isolation: mode})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			// The fixture manifest covers meta.json and advisories.sqlite.
			want := 4
			if mode == "copy" {
				want = 6
			} else if mode == "auto" || mode == "none" {
				want = 2 // SQLite is hashed through its already-open descriptor.
			}
			if ctx.calls != want {
				t.Fatalf("hash boundary calls=%d want=%d", ctx.calls, want)
			}
		})
	}
}

func TestIsolationSkipOverridesModeAndFailedOpenReleasesLock(t *testing.T) {
	dir := readerCatalog(t)
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy", SkipIsolation: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.(*sqliteStore).snapshot != "" {
		t.Fatal("SkipIsolation did not override copy")
	}
	unlock, err := lockDatabase(dir)
	if err != nil {
		t.Fatal("none retained lock", err)
	}
	unlock()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	alterReaderCatalog(t, dir, "PRAGMA user_version=3")
	for _, mode := range []string{"auto", "copy", "none"} {
		if st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: mode}); err == nil {
			st.Close()
			t.Fatal("old schema accepted")
		}
		unlock, err := lockDatabase(dir)
		if err != nil {
			t.Fatal("failed open retained lock", err)
		}
		unlock()
	}
}

func TestIsolationCopyRechecksSnapshotIntegrity(t *testing.T) {
	dir := readerCatalog(t)
	ctx := &replaceAfterVerification{Context: context.Background(), replace: func() {
		f, err := os.OpenFile(filepath.Join(dir, SQLiteFileName), os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteAt([]byte("tampered"), 100)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}}
	st, err := OpenWithOptionsContext(ctx, dir, Options{Isolation: "copy"})
	if err == nil {
		st.Close()
		t.Fatal("snapshot checksum not rechecked")
	}
	if !strings.Contains(err.Error(), "changed while") {
		t.Fatal(err)
	}
}
