package scan

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryReviewRejectsImpostorsAndAmbiguity(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"nginx-exporter", "ngx_http nginx/1.20.0"},
		{"python3-helper", "Py_InitializeEx Python 3.12.0"},
		{"redis-exporter", "redis-server Redis version 7.2.4"},
		{"nginx", "User-Agent: nginx/1.20.0"},
		{"python3", "Python 3.12.0"},
		{"node", "node/v22.12.0"},
		{"openssl", "OpenSSL 3.0.13"},
		{"curl", "curl_easy_init curl 7.0.0\x00curl 8.9.1"},
		{"python3.12", "Py_InitializeEx Python 3.12.1\x003.12.2 (main, today)"},
	} {
		t.Run(tc.name+tc.text, func(t *testing.T) {
			data := []byte("\x7fELF\x00" + tc.text + "\x00")
			if got := binaryPackages(bytes.NewReader(data), int64(len(data)), tc.name, ""); len(got) != 0 {
				t.Fatalf("false classification: %+v", got)
			}
		})
	}
}

func TestBinaryReviewImageSkipAndReserve(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprint(skip), func(t *testing.T) {
			u := newUnpacker(context.Background(), Options{SkipBinaries: skip})
			defer u.Close()
			if !skip {
				u.binaryBudget.count.Store(maxClassifiedBinaries)
			}
			data := make([]byte, 1<<20)
			copy(data, "\x7fELF\x00curl_easy_init curl 8.9.1\x00")
			r := &binaryReviewStream{Reader: bytes.NewReader(data)}
			f, err := u.readEntry("bin/curl", r, &tar.Header{Size: int64(len(data)), Mode: 0755}, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(u.binaries) != 0 {
				t.Fatal("binary classified despite skip/budget")
			}
			if r.largest > 64<<10 {
				t.Fatalf("full binary buffer requested: %d", r.largest)
			}
			if f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
				t.Fatal("hash changed")
			}
			if skip && u.binaryBudget.count.Load() != 0 {
				t.Fatal("skip consumed budget")
			}
		})
	}
}

type binaryReviewStream struct {
	io.Reader
	largest int
}

func (r *binaryReviewStream) Read(p []byte) (int, error) {
	r.largest = max(r.largest, len(p))
	return r.Reader.Read(p)
}

func TestBinaryReviewRenamedTrue(t *testing.T) {
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Skip(err)
	}
	data = append(data, []byte("\x00User-Agent: nginx/1.20.0\x00")...)
	root := t.TempDir()
	for _, name := range []string{"nginx", "nginx-exporter"} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	result, err := DirectoryContext(context.Background(), root, "impostors", Options{IncludeFileHashes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Packages) != 0 {
		t.Fatalf("renamed true classified: %+v", result.Packages)
	}
	if len(result.Files) != 2 {
		t.Fatalf("missing impostor files: %+v", result.Files)
	}
	for _, file := range result.Files {
		if file.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
			t.Fatalf("hash changed: %+v", file)
		}
	}
}

// Signature fixtures must include independent product evidence.
func binaryReviewMarker(name string) string {
	return map[string]string{"python": "Py_InitializeEx", "node": "NODE_OPTIONS", "ruby": "RUBYLIB", "openssl": "OPENSSLDIR", "busybox": "multi-call binary", "php": "PHP_INI_SCAN_DIR", "perl": "PERL5LIB", "nginx": "ngx_http", "httpd": "ap_server_root", "redis": "redis-server", "postgres": "PGDATA", "mariadb": "MYSQL_HOME", "mysql": "MYSQL_HOME", "curl": "curl_easy_init", "bash": "BASHOPTS"}[name]
}

func TestBinaryReviewImageBudgetMetadata(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "budget-*.tar")
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(file)
	data := []byte("\x7fELF\x00curl_easy_init curl 8.9.1\x00")
	for i := 0; i <= maxClassifiedBinaries; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("bin/%d", i), Mode: 0755, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, scan := range []struct {
		name string
		run  func() (Result, error)
	}{
		{"archive", func() (Result, error) { return Archive(file.Name(), Options{}) }},
		{"rootfs", func() (Result, error) { return rootfsArchive(context.Background(), file.Name(), Options{}) }},
	} {
		t.Run(scan.name, func(t *testing.T) {
			r, err := scan.run()
			if err != nil {
				t.Fatal(err)
			}
			if r.Scan == nil || !r.Scan.Partial || r.Scan.LimitReached != "max-binaries" {
				t.Fatalf("missing limit metadata: %+v", r.Scan)
			}
		})
	}
}

func binaryReviewLargeELF() []byte {
	data := make([]byte, 16<<20)
	copy(data, "\x7fELF\x02\x01\x01")
	bo := binary.LittleEndian
	bo.PutUint16(data[16:], 2)
	bo.PutUint16(data[18:], 62)
	bo.PutUint32(data[20:], 1)
	bo.PutUint64(data[32:], 64)
	bo.PutUint16(data[52:], 64)
	bo.PutUint16(data[54:], 56)
	bo.PutUint16(data[56:], 1)
	bo.PutUint32(data[64:], 1)
	bo.PutUint32(data[68:], 6)
	bo.PutUint64(data[72:], 512)
	bo.PutUint64(data[80:], 4096)
	bo.PutUint64(data[96:], uint64(len(data)-512))
	bo.PutUint64(data[104:], uint64(len(data)-512))
	bo.PutUint64(data[40:], 128)
	bo.PutUint16(data[58:], 64)
	bo.PutUint16(data[60:], 3)
	bo.PutUint16(data[62:], 1)
	names := []byte("\x00.shstrtab\x00.go.buildinfo\x00")
	copy(data[400:], names)
	bo.PutUint32(data[192:], 1)
	bo.PutUint32(data[196:], 3)
	bo.PutUint64(data[216:], 400)
	bo.PutUint64(data[224:], uint64(len(names)))
	bo.PutUint32(data[256:], 11)
	bo.PutUint32(data[260:], 1)
	bo.PutUint64(data[272:], 4096)
	bo.PutUint64(data[280:], 512)
	bo.PutUint64(data[288:], uint64(len(data)-512))
	return data
}

func TestBinaryReviewGoReadCap(t *testing.T) {
	data := binaryReviewLargeELF()
	r := &binaryCountingReader{ReaderAt: bytes.NewReader(data)}
	if got := goBinaryPackages(r, int64(len(data)), "app", ""); len(got) != 0 {
		t.Fatal(got)
	}
	t.Logf("16 MiB ELF build-info probe read %d bytes", r.read)
	if r.read < 4<<20 {
		t.Fatalf("fixture did not exercise large section reads: %d", r.read)
	}
	if r.read > maxBinaryScanBytes {
		t.Fatalf("build-info read %d bytes; cap %d", r.read, maxBinaryScanBytes)
	}
}

func TestBinaryReviewGoSectionCount(t *testing.T) {
	for _, count := range []uint16{4097, 0} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			data := binaryReviewLargeELF()
			binary.LittleEndian.PutUint64(data[40:], 256)
			binary.LittleEndian.PutUint16(data[58:], 64)
			binary.LittleEndian.PutUint16(data[60:], count)
			if count == 0 {
				binary.LittleEndian.PutUint64(data[256+32:], 4097)
			}
			r := &binaryCountingReader{ReaderAt: bytes.NewReader(data)}
			if got := goBinaryPackages(r, int64(len(data)), "app", ""); len(got) != 0 {
				t.Fatal(got)
			}
			if r.read > 64 {
				t.Fatalf("oversize section table reached parser: %d bytes", r.read)
			}
		})
	}
}

func TestBinaryReviewAmbiguityLogging(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var events []Progress
		opts := Options{Verbose: verbose, Progress: func(p Progress) { events = append(events, p) }}
		data := []byte("\x7fELF\x00curl_easy_init\x00curl 7.0.0\x00curl 8.9.1\x00")
		if got := binaryPackages(bytes.NewReader(data), int64(len(data)), "curl", "", opts); len(got) != 0 {
			t.Fatal(got)
		}
		if !verbose && len(events) != 0 {
			t.Fatalf("nonverbose ambiguity log: %+v", events)
		}
		if verbose && (len(events) != 1 || !strings.Contains(events[0].Message, "ambiguous curl version (2 distinct candidates)") || !events[0].Detail) {
			t.Fatalf("missing ambiguity count: %+v", events)
		}
	}
}

func TestBinaryReviewLibraryAndDuplicateVersions(t *testing.T) {
	for _, name := range []string{"curl", "curl.exe", "libcurl.so", "libcurl.so.4.8.0"} {
		text := "curl 8.9.1"
		if strings.HasPrefix(name, "lib") {
			text = "libcurl/8.9.1"
		}
		data := []byte("\x7fELF\x00curl_easy_init\x00" + text + "\x00" + text + "\x00")
		if got := binaryPackages(bytes.NewReader(data), int64(len(data)), name, ""); len(got) != 1 || got[0].Version != "8.9.1" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	for _, name := range []string{"libcurl.so.fake", "libpython3.12.so-helper", "libssl.so.3.bak", "ruby3.2-helper", "busybox-helper", "php8.3-helper", "libz.so.fake", "libc.so.6.bak", "bash-helper"} {
		if got := binaryRules(name); len(got) != 0 {
			t.Fatalf("unapproved suffix: %s", name)
		}
	}
}

func TestBinaryReviewImageLargeHashOnly(t *testing.T) {
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	data := make([]byte, maxBinaryScanBytes+1)
	copy(data, "\x7fELF\x00curl_easy_init curl 8.9.1\x00")
	r := &binaryReviewStream{Reader: bytes.NewReader(data)}
	f, err := u.readEntry("bin/curl", r, &tar.Header{Size: int64(len(data)), Mode: 0755}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.binaries) != 0 || u.binaryBudget.count.Load() != 0 || r.largest > 64<<10 || f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatalf("oversize entry probed: binaries=%v probes=%d read=%d", u.binaries, u.binaryBudget.count.Load(), r.largest)
	}
}

func TestBinaryReviewImageSharedReadBudget(t *testing.T) {
	original := extractGoBinary
	t.Cleanup(func() { extractGoBinary = original })
	extractGoBinary = func(r io.ReaderAt, _ int64, _, _ string) []Package {
		buf := make([]byte, 1<<20)
		for range 8 {
			if _, err := r.ReadAt(buf, 0); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	data := make([]byte, 1<<20)
	copy(data, "\x7fELF\x00curl_easy_init curl 8.9.1\x00")
	if _, err := u.readEntry("bin/curl", bytes.NewReader(data), &tar.Header{Size: int64(len(data)), Mode: 0755}, ""); err != nil {
		t.Fatal(err)
	}
	if len(u.binaries) != 0 {
		t.Fatal("classifier read after build-info spent the shared budget")
	}
}

func TestBinaryReviewBudgetMetadataMerge(t *testing.T) {
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	result := Result{Scan: &ScanMetadata{Partial: true, LimitReached: "max-total-bytes", MetadataSkipped: 2}}
	u.binaryBudget.count.Store(maxClassifiedBinaries)
	u.applyBinaryMetadata(&result)
	if result.Scan.LimitReached != "max-total-bytes" {
		t.Fatal("exact budget boundary marked partial")
	}
	u.binaryBudget.take()
	u.applyBinaryMetadata(&result)
	u.applyBinaryMetadata(&result)
	if result.Scan.LimitReached != "max-total-bytes,max-binaries" || result.Scan.MetadataSkipped != 2 {
		t.Fatalf("metadata lost/duplicated: %+v", result.Scan)
	}
}
