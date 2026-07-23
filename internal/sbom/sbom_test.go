package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestDocumentsAreValidJSONWithComponents(t *testing.T) {
	r := scan.Result{Name: "image", SourceType: "docker-image", SourceHash: "abc", ScannedAt: time.Unix(1, 0).UTC(),
		Packages: []scan.Package{{Name: "libc", Version: "1.0", Type: "apk", PURL: "pkg:apk/libc@1.0"}},
		Files:    []scan.File{{Path: "bin/x", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	for name, fn := range map[string]func(scan.Result) ([]byte, error){"spdx": SPDX, "cdx": CycloneDX} {
		b, err := fn(r)
		if err != nil || !json.Valid(b) {
			t.Fatalf("%s: %v %s", name, err, b)
		}
		var doc map[string]any
		json.Unmarshal(b, &doc)
		if name == "spdx" && doc["spdxVersion"] != "SPDX-2.3" {
			t.Fatal("wrong SPDX version")
		}
		if name == "cdx" && doc["specVersion"] != "1.6" {
			t.Fatal("wrong CycloneDX version")
		}
	}
}
