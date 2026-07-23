package hash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestVerifyAndTamper(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "artifact")
	if err := os.WriteFile(p, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, _ := File(p)
	m := filepath.Join(d, "artifact.sha256")
	if err := Write(m, []Entry{{Digest: sum, Path: "artifact"}}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(m); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("changed"), 0o644)
	if err := Verify(m); err == nil {
		t.Fatal("changed file accepted")
	}
}
