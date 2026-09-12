//go:build linux

package vulndb

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReviewCrashedReaderHelper(t *testing.T) {
	dir := os.Getenv("BSCAN_REVIEW_CRASH_DB")
	if dir == "" {
		return
	}
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	if st.(*sqliteStore).snapshot == "" {
		t.Fatal("no snapshot")
	}
	// Simulate an abrupt exit: no Close and no Go deferred cleanup.
	os.Exit(0)
}

func TestReviewReaderReapsDeadOwnersAndPreservesLiveOwners(t *testing.T) {
	dir := readerCatalog(t)
	live, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReviewCrashedReaderHelper$")
	cmd.Env = append(os.Environ(), "BSCAN_REVIEW_CRASH_DB="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crashed reader helper: %s %v", out, err)
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(dir), ".bscan-db-reader-*"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("expected live and dead snapshots: %v %v", paths, err)
	}
	next, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	for _, path := range paths {
		_, err := os.Stat(path)
		if path == live.(*sqliteStore).snapshot {
			if err != nil {
				t.Fatal("live snapshot deleted", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dead snapshot retained: %s %v", path, err)
		}
	}
	if got, err := live.Lookup("npm", "example"); err != nil || len(got) != 1 {
		t.Fatal("live lookup damaged", got, err)
	}
}

func TestReviewReaderPreservesUnmarkedOldCopies(t *testing.T) {
	dir := readerCatalog(t)
	old, err := os.MkdirTemp(filepath.Dir(dir), ".bscan-db-reader-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(old, SQLiteFileName), []byte("older reader snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = os.Stat(filepath.Join(old, SQLiteFileName)); err != nil {
		t.Fatal("unmarked reader might still be alive", err)
	}
}
