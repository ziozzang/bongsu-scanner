package sbom

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestAnalysisSBOMPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not implement Unix permission bits")
	}
	for _, format := range []string{"spdx", "cyclonedx"} {
		path := filepath.Join(t.TempDir(), "inventory.json")
		if err := Write(path, format, scan.Result{Name: "private-inventory"}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s inventory readable by other users: %o", format, info.Mode().Perm())
		}
	}
}
