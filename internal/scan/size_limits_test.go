package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Limit overrides are only for serial tests. Cleanup also runs after Fatal;
// all scanner workers must finish before the test returns.
func setTestLimit(t *testing.T, limit *int64, value int64) {
	t.Helper()
	old := *limit
	*limit = value
	t.Cleanup(func() { *limit = old })
}

func smallRPMTestLimits(t *testing.T) {
	t.Helper()
	setTestLimit(t, &maxFileMetadata, 1<<20)
	setTestLimit(t, &maxRPMDatabase, 2<<20)
}

func TestSizeLimitDefaults(t *testing.T) {
	if maxLayerBytes != 16<<30 || maxRPMDatabase != 256<<20 || maxFileMetadata != 16<<20 || maxGoBinary != 64<<20 || defaultMaxTotalBytes != 512<<20 {
		t.Fatalf("unexpected defaults: layer=%d RPM=%d metadata=%d Go=%d retention=%d", maxLayerBytes, maxRPMDatabase, maxFileMetadata, maxGoBinary, defaultMaxTotalBytes)
	}
}

func TestDefaultOuterDecompressionLimit(t *testing.T) {
	setTestLimit(t, &maxLayerBytes, 2<<20)
	for _, size := range []int64{maxLayerBytes - 1, maxLayerBytes, maxLayerBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// Padding after tar EOF must count even with no MaxTotalBytes option.
			p := writeTemp(t, "padding.zst", zstdBytes(t, make([]byte, size)))
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			a, err := indexOuter(context.Background(), p, formatZstd, true, Options{})
			if a != nil {
				a.Close()
			}
			if size <= maxLayerBytes && err != nil || size > maxLayerBytes && (err == nil || !strings.Contains(err.Error(), "decompression limit exceeded")) {
				t.Fatalf("size=%d limit=%d: %v", size, maxLayerBytes, err)
			}
			if entries, err := os.ReadDir(tmp); err != nil || len(entries) != 0 {
				t.Fatalf("decompression leaked temporary files: %v, %v", entries, err)
			}
		})
	}
}

func TestMetadataSizeLimit(t *testing.T) {
	setTestLimit(t, &maxFileMetadata, 1<<20)
	testMetadataSizeLimit(t)
}

func testMetadataSizeLimit(t *testing.T) {
	for _, size := range []int64{maxFileMetadata - 1, maxFileMetadata, maxFileMetadata + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			body := bytes.Repeat([]byte(" "), int(size))
			copy(body, "module app\nrequire example.com/dep v1.0.0\n")
			keep := size <= maxFileMetadata
			u := newUnpacker(context.Background(), Options{})
			defer u.Close()
			f, err := u.readEntry("go.mod", bytes.NewReader(body), &tar.Header{Size: size}, "layer")
			if err != nil || (f.Data != nil) != keep || f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) {
				t.Fatalf("image metadata: retained=%d size=%d err=%v", len(f.Data), size, err)
			}

			p := writeTemp(t, "outer.gz", gzipBytes(t, buildTar(t, []tarEntry{{name: "go.mod", data: body}})))
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			a, err := indexOuter(context.Background(), p, formatGzip, true, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err := a.retain([]string{"go.mod"}); err != nil {
				t.Fatal(err)
			}
			e := a.entries["go.mod"]
			if (e.data != nil) != keep || (e.temp != "") == keep {
				t.Fatalf("outer metadata: retained=%d spilled=%t size=%d", len(e.data), e.temp != "", size)
			}
			got, err := a.bytes("go.mod")
			if keep && (err != nil || !bytes.Equal(got, body)) || !keep && err == nil {
				t.Fatalf("outer metadata read: size=%d err=%v", size, err)
			}
			a.Close()
			if entries, err := os.ReadDir(tmp); err != nil || len(entries) != 0 {
				t.Fatalf("spool leaked: %v, %v", entries, err)
			}

			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "go.mod"), body, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true})
			if err != nil {
				t.Fatal(err)
			}
			if keep && (len(r.Packages) != 1 || r.Scan.MetadataSkipped != 0 || r.Scan.Partial) || !keep && (len(r.Packages) != 0 || r.Scan.MetadataSkipped != 1 || !r.Scan.Partial) {
				t.Fatalf("walk metadata: packages=%d scan=%+v", len(r.Packages), r.Scan)
			}
		})
	}
}

func TestGoBinarySizeLimit(t *testing.T) {
	setTestLimit(t, &maxGoBinary, 1<<20)
	testGoBinarySizeLimit(t)
}

func testGoBinarySizeLimit(t *testing.T) {
	original := extractGoBinary
	t.Cleanup(func() { extractGoBinary = original })
	for _, size := range []int64{maxGoBinary - 1, maxGoBinary, maxGoBinary + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			calls := 0
			extractGoBinary = func(_ io.ReaderAt, gotSize int64, source, layer string) []Package {
				calls++
				if gotSize != size || source != "bin/app" || layer != "layer" {
					t.Errorf("binary attribution: size=%d source=%s layer=%s", gotSize, source, layer)
				}
				return nil
			}
			body := make([]byte, size)
			copy(body, "\x7fELF")
			u := newUnpacker(context.Background(), Options{})
			defer u.Close()
			f, err := u.readEntry("bin/app", bytes.NewReader(body), &tar.Header{Size: size, Mode: 0755}, "layer")
			wantCalls := 0
			if size <= maxGoBinary {
				wantCalls = 1
			}
			if err != nil || calls != wantCalls || f.Data != nil || f.Size != size || f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) {
				t.Fatalf("binary cap: calls=%d want=%d retained=%d err=%v", calls, wantCalls, len(f.Data), err)
			}
		})
	}
}

// Run production-size boundaries explicitly with:
// BSCAN_HEAVY_TESTS=1 go test -race -run '^TestProductionSizeLimits$' ./internal/scan/
func TestProductionSizeLimits(t *testing.T) {
	if os.Getenv("BSCAN_HEAVY_TESTS") != "1" {
		t.Skip("set BSCAN_HEAVY_TESTS=1 to exercise production-size limits")
	}
	t.Run("decompression", testZstdDecompressionBomb)
	t.Run("rpm-image", testImageRPMOCI)
	t.Run("rpm-walk", testRPMWalkCapsHashesAndCorruption)
	t.Run("metadata", testMetadataSizeLimit)
	t.Run("go-binary", testGoBinarySizeLimit)
	t.Run("outer-retention", func(t *testing.T) { testImageReviewOuterRetention(t, 8<<20) })
}
