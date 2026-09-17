package scan_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/sbom"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestVersionOriginalSBOM(t *testing.T) {
	r := scan.Result{Name: "fixture", Packages: []scan.Package{{Name: "ecj", Namespace: "org.eclipse.jdt", Version: "3.33.0", VersionOriginal: "3.33.0.v20230218-1114", Type: "maven", PURL: "pkg:maven/org.eclipse.jdt/ecj@3.33.0"}}}
	for name, render := range map[string]func(scan.Result) ([]byte, error){"cyclonedx": sbom.CycloneDX, "spdx": sbom.SPDX} {
		t.Run(name, func(t *testing.T) {
			b, err := render(r)
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(b) || !strings.Contains(string(b), "bscan:version-original") || !strings.Contains(string(b), r.Packages[0].VersionOriginal) {
				t.Fatalf("original version missing: %s", b)
			}
			r.Packages[0].VersionOriginal = ""
			b, err = render(r)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "bscan:version-original") {
				t.Fatalf("empty original emitted: %s", b)
			}
			r.Packages[0].VersionOriginal = "3.33.0.v20230218-1114"
		})
	}
}
