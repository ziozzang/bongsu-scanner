package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var cliDBFixture struct {
	once sync.Once
	temp string
	root string
	dir  string
}

func TestMain(m *testing.M) {
	// Individual tests may redirect TMPDIR and inspect it for leaked scratch files.
	cliDBFixture.temp = os.TempDir()
	code := m.Run()
	if cliDBFixture.root != "" {
		if err := os.RemoveAll(cliDBFixture.root); err != nil {
			fmt.Fprintln(os.Stderr, "remove CLI database fixture:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// The catalog payload is read-only; normal verification may create its receipt.
// Keep its inode alive until TestMain cleanup so readers also share ctime settlement.
// Tests that sign, corrupt, rename or recover a catalog must use privateCLITestDB.
func cliTestDB(t *testing.T) string {
	t.Helper()
	cliDBFixture.once.Do(func() {
		var err error
		cliDBFixture.root, err = os.MkdirTemp(cliDBFixture.temp, "bscan-cli-db-")
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(cliDBFixture.root, "db")
		buildCLITestDB(t, dir)
		cliDBFixture.dir = dir
	})
	if cliDBFixture.dir == "" {
		t.Fatal("shared CLI database fixture initialization failed")
	}
	return cliDBFixture.dir
}

func privateCLITestDB(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db")
	if err := os.CopyFS(dir, os.DirFS(cliTestDB(t))); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCLITestDBReusesReadOnlyFixture(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	var first string
	t.Run("initialize", func(t *testing.T) { first = cliTestDB(t) })
	t.Run("reuse-after-cleanup", func(t *testing.T) {
		if second := cliTestDB(t); second != first {
			t.Fatalf("rebuilt read-only database: %s != %s", second, first)
		}
		if _, err := os.Stat(filepath.Join(first, "manifest.sha256")); err != nil {
			t.Fatalf("fixture did not survive initializing test cleanup: %v", err)
		}
		if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
			t.Fatalf("shared fixture used caller's temporary directory: %v (%v)", entries, err)
		}
	})
}

func TestCLITestDBMutationIsolation(t *testing.T) {
	shared := cliTestDB(t)
	before, err := os.ReadFile(filepath.Join(shared, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	private := privateCLITestDB(t)
	if err := os.WriteFile(filepath.Join(private, "manifest.sha256"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(private, private+".prev"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(cliTestDB(t), "manifest.sha256"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("private mutation changed shared catalog: %v", err)
	}
}
