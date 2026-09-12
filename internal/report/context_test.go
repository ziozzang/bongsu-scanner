package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/sbom"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestSBOMContextRoundtrip(t *testing.T) {
	original := scan.Result{Name: "docker://fixture", SourceType: "docker", ScannedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), OS: &scan.OSRelease{ID: "debian", IDLike: "linux", VersionID: "13", Codename: "trixie", PrettyName: "Debian 13"}, Scan: &scan.ScanMetadata{Partial: true, EUID: 1000, PermissionDenied: 2, MetadataSkipped: 7, SkippedErrors: 3, SkippedPaths: []string{"/secret"}, Excluded: []string{"/proc", "/sys"}, ExcludedCount: 5, FilesVisited: 123, InContainer: true, LimitReached: "max-files"}, Host: &scan.HostMetadata{Hostname: "fixture", OperatingSystem: "linux", OSVersion: "13", Kernel: "6", Architecture: "amd64", CPUModel: "test", CPUCount: 8, MemoryBytes: 123456, IPAddresses: []string{"127.0.0.1", "::1"}}, Image: &scan.ImageMetadata{ID: "sha256:abcdef", Digest: "sha256:01234", Tags: []string{"test:latest"}, RepoDigests: []string{"test@sha256:01234"}, OS: "linux", Architecture: "amd64", Variant: "v1", Created: "2026-01-01", ContainerID: "container", Layers: []scan.LayerInfo{{Digest: "sha256:layer0", DiffID: "sha256:diff0", Verified: true}, {Digest: "sha256:layer1", DiffID: "sha256:diff1", Verified: false}}}}
	for name, encode := range map[string]func(scan.Result) ([]byte, error){"cyclonedx": sbom.CycloneDX, "spdx": sbom.SPDX} {
		t.Run(name, func(t *testing.T) {
			b, err := encode(original)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "sbom.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			target, s, o, i, h, err := ContextFromSBOM(path)
			if err != nil {
				t.Fatal(err)
			}
			if target != original.Name || !reflect.DeepEqual(s, original.Scan) || !reflect.DeepEqual(o, original.OS) || !reflect.DeepEqual(i, original.Image) || !reflect.DeepEqual(h, original.Host) {
				t.Fatalf("context mismatch\ntarget=%s\nscan=%+v\nos=%+v\nimage=%+v\nhost=%+v", target, s, o, i, h)
			}
		})
	}
}
func TestContextAbsentAndMalformed(t *testing.T) {
	for _, s := range []string{`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"empty"}}}`, `{"spdxVersion":"SPDX-2.3","name":"empty","packages":[]}`} {
		path := filepath.Join(t.TempDir(), "bom.json")
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		target, scan, os, image, host, err := ContextFromSBOM(path)
		if err != nil || target != "empty" || scan != nil || os != nil || image != nil || host != nil {
			t.Fatalf("absent metadata: %s %v %v %v %v %v", target, scan, os, image, host, err)
		}
	}
	for _, s := range []string{`{`, `{}`, `null`, `{"bomFormat":"CycloneDX","metadata":{"component":{"properties":[{"name":"bscan:scan:euid","value":"bad"}]}}}`, `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Root","annotations":[{"comment":"bscan scan metadata: broken"}]}]}`} {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, err := ContextFromSBOM(path); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	if _, _, _, _, _, err := ContextFromSBOM(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
func TestContextLayerOrderAndExcludedCount(t *testing.T) {
	properties := []any{}
	for _, n := range []int{10, 2, 0} {
		properties = append(properties, map[string]string{"name": "bscan:image:layer:" + map[int]string{10: "10", 2: "2", 0: "0"}[n], "value": "layer" + map[int]string{10: "10", 2: "2", 0: "0"}[n] + " verified=true"})
	}
	properties = append(properties, map[string]string{"name": "bscan:scan:excluded", "value": "/a;/b"})
	doc := map[string]any{"bomFormat": "CycloneDX", "metadata": map[string]any{"component": map[string]any{"properties": properties}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	_, s, _, image, _, err := ContextFromSBOM(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExcludedCount != 2 || len(image.Layers) != 3 || image.Layers[0].Digest != "layer0" || image.Layers[2].Digest != "layer10" {
		t.Fatalf("scan=%+v image=%+v", s, image)
	}
}
