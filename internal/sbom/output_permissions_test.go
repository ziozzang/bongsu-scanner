package sbom

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestSBOMFilesAreReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.cdx.json")
	r := scan.Result{Name: "x", SourceType: "directory", ScannedAt: time.Unix(0, 0).UTC()}
	if err := Write(path, "cyclonedx", r); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 == 0 {
		t.Fatalf("SBOM mode = %v, want group/other readable", info.Mode().Perm())
	}
}
