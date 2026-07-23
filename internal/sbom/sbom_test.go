package sbom

import (
	"encoding/json"
	"strings"
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

func TestHostMetadataIncludedInBothFormats(t *testing.T) {
	r := scan.Result{Name: "host", SourceType: "host", ScannedAt: time.Unix(1, 0).UTC(),
		Host: &scan.HostMetadata{Hostname: "build-host", OperatingSystem: "linux", OSVersion: "42",
			Kernel: "6.1-test", Architecture: "amd64", CPUModel: "Test CPU", CPUCount: 8,
			MemoryBytes: 17179869184, IPAddresses: []string{"10.0.0.2", "2001:db8::2"}},
		Packages: []scan.Package{{Name: "local-module", Version: "1", Type: "golang", Source: "/home/foo/app/go.mod"}}}
	for name, fn := range map[string]func(scan.Result) ([]byte, error){"spdx": SPDX, "cdx": CycloneDX} {
		b, err := fn(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"build-host", "Test CPU", "17179869184", "10.0.0.2", "/home/foo/app/go.mod"} {
			if !strings.Contains(string(b), value) {
				t.Errorf("%s missing host metadata %q", name, value)
			}
		}
	}
}
