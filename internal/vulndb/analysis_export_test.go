package vulndb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalysisExportRejectsReplacedEntry(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "catalog")
	if err := os.WriteFile(name, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	f, err := openExportFile(root, "catalog", info)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, name+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := openExportFile(root, "catalog", info); err == nil {
		_ = f.Close()
		t.Fatal("accepted a different inode after directory traversal")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("private data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, name); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if f, err := openExportFile(root, "catalog", info); err == nil {
		_ = f.Close()
		t.Fatal("followed a symlink outside the export root")
	}
}
