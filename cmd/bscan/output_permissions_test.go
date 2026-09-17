package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Deliverable outputs (findings, reports) are world-readable subject to the
// umask so other users, CI collectors and containers can consume them.
func TestDeliverableOutputsAreReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := writeCommandOutput(path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 == 0 {
		t.Fatalf("findings output mode = %v, want group/other readable", info.Mode().Perm())
	}
}
