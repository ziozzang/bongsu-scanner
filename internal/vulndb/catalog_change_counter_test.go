package vulndb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogHeaderDetectsSameTickVerificationMutation(t *testing.T) {
	dir := readerCatalog(t)
	source, err := openCatalogFile(filepath.Join(dir, SQLiteFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer source.file.Close()
	if err := source.check("catalog changed during verification"); err != nil {
		t.Fatal(err)
	}
	alterReaderCatalog(t, dir, "DELETE FROM records")
	coalesceCatalogStat(t, source)
	if err := source.check("catalog changed during verification"); err == nil || err.Error() != "catalog changed during verification" {
		t.Fatalf("same-tick mutation during verification: %v", err)
	}
}

func TestCatalogHeaderDetectsMutationDuringLookup(t *testing.T) {
	dir := readerCatalog(t)
	// Exercise the in-place check even on filesystems that support reflinks.
	st, err := OpenWithOptionsContext(context.Background(), dir, Options{Isolation: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := st.(*sqliteStore)
	visited := 0
	err = s.LookupFunc(context.Background(), "npm", "example", func(*Record) error {
		visited++
		alterReaderCatalog(t, dir, "DELETE FROM records")
		coalesceCatalogStat(t, s.source)
		return nil
	})
	if visited != 1 || err == nil || !strings.Contains(err.Error(), "catalog modified during read") {
		t.Fatalf("mutation in callback: visited=%d err=%v", visited, err)
	}
	if err := st.Close(); err == nil || !strings.Contains(err.Error(), "catalog modified during read") {
		t.Fatalf("Close after mutation: %v", err)
	}
}

// Keep the inode and size fixed, and make the captured stat indistinguishable
// from a fresh fstat. This deterministically simulates a timestamp collision
// without waiting for (or relying on) the host filesystem's clock resolution.
func coalesceCatalogStat(t *testing.T, source *catalogFile) {
	t.Helper()
	after, err := source.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(source.info, after) || source.info.Size() != after.Size() {
		t.Fatal("mutation must preserve inode and size to model a timestamp collision")
	}
	source.info = after
}
