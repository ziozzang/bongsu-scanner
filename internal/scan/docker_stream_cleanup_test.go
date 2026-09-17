package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A cancelled docker export must leave no temporary archive behind: the
// output is streamed into a file bscan owns, and that file is removed on
// failure. (docker's own -o flag would leave a ".tmp-*" sibling.)
func TestDockerExportCancelLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	script := "#!/bin/sh\ncase \"$1 $2\" in\n  \"container inspect\") printf 'abcdef0123456789|sha256:%s|/slow|running\\n' \"$(printf '%064d' 7)\" ;;\n  \"export \"*) i=0; while [ $i -lt 100 ]; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; sleep 0.05; i=$((i+1)); done ;;\n  \"image inspect\") printf '{\"Id\":\"sha256:%s\"}\\n' \"$(printf '%064d' 7)\" ;;\n  *) exit 2 ;;\nesac\n"
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := Target(ctx, "container://slow", Options{Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected cancellation error, got %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "bin" {
			t.Fatalf("temporary file left behind after cancellation: %s", e.Name())
		}
	}
}
