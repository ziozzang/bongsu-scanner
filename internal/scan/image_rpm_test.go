package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Stream the fixture so even the opt-in full-size case needs no large slice.
func imageRPMLayer(t *testing.T, db, name string, links []tarEntry) ([]byte, string) {
	t.Helper()
	f, err := os.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	sum := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(gz, sum))
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: st.Size()}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		t.Fatal(err)
	}
	osRelease := []byte("ID=rocky\nVERSION_ID=9.4\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0644, Size: int64(len(osRelease))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(osRelease); err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if err := tw.WriteHeader(&tar.Header{Name: link.name, Typeflag: link.typeflag, Linkname: link.link, Mode: 0644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func imageRPMArchive(t *testing.T, blobs [][]byte, diffIDs []string) string {
	t.Helper()
	entries := map[string][]byte{}
	desc := ociBlobs(t, entries, ociImage{layers: blobs, diffIDs: diffIDs}, nil)
	return writeTemp(t, "rpm-image.tar", ociLayoutTar(t, entries, ociIndex{MediaType: mediaTypeOCIIndex, Manifests: []ociDescriptor{desc}}))
}

func assertImageRPM(t *testing.T, r Result, epoch int, source string) {
	t.Helper()
	if len(r.Packages) != 1 {
		t.Fatalf("packages = %+v", r.Packages)
	}
	p := r.Packages[0]
	if p.Type != "rpm" || p.Version != fmt.Sprintf("%d:1.2-3.el9", epoch) || p.Source != source || p.Layer == "" || !strings.HasPrefix(p.PURL, "pkg:rpm/rocky/Lib-example@1.2-3.el9?") || !strings.Contains(p.PURL, "distro=rocky-9.4") || !strings.Contains(p.PURL, "upstream=example-src") {
		t.Fatalf("package = %+v", p)
	}
	if f := filesByPath(r)[source]; f.Data != nil || f.SHA256 == "" {
		t.Fatalf("RPM must be hashed without retained bytes: size=%d data=%d", f.Size, len(f.Data))
	}
}

func TestImageRPMOCI(t *testing.T) {
	smallRPMTestLimits(t)
	testImageRPMOCI(t)
}

func testImageRPMOCI(t *testing.T) {
	for _, size := range []int64{0, maxFileMetadata + 4096, maxRPMDatabase, maxRPMDatabase + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			db := rpmTestSQLite(t, rpmTestHeader(2))
			if size != 0 {
				if err := os.Truncate(db, size); err != nil {
					t.Fatal(err)
				}
			}
			blob, diffID := imageRPMLayer(t, db, "var/lib/rpm/rpmdb.sqlite", nil)
			archive := imageRPMArchive(t, [][]byte{blob}, []string{diffID})
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			r, err := Archive(archive, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if size > maxRPMDatabase {
				if len(r.Packages) != 0 || r.Scan == nil || r.Scan.MetadataSkipped != 1 || !r.Scan.Partial {
					t.Fatalf("oversized RPM: packages=%d scan=%+v", len(r.Packages), r.Scan)
				}
			} else {
				assertImageRPM(t, r, 2, "var/lib/rpm/rpmdb.sqlite")
			}
			entries, err := os.ReadDir(tmp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestImageRPMLinksAndLayers(t *testing.T) {
	smallRPMTestLimits(t)
	const rpmPath = "var/lib/rpm/rpmdb.sqlite"
	db := rpmTestSQLite(t, rpmTestHeader(2))
	if err := os.Truncate(db, maxFileMetadata+4096); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			target := "payload/database"
			link := target
			if typ == tar.TypeSymlink {
				link = "/" + target
			}
			blob, diffID := imageRPMLayer(t, db, target, []tarEntry{{name: rpmPath, typeflag: typ, link: link}})
			// A hardlink retains the old bytes; a symlink resolves the final target.
			replacement := rpmTestSQLite(t, rpmTestHeader(3))
			next, nextID := imageRPMLayer(t, replacement, target, nil)
			archive := imageRPMArchive(t, [][]byte{blob, next}, []string{diffID, nextID})
			r, err := Archive(archive, Options{})
			if err != nil {
				t.Fatal(err)
			}
			epoch := 2
			if typ == tar.TypeSymlink {
				epoch = 3
			}
			assertImageRPM(t, r, epoch, rpmPath)
		})
	}
	for _, action := range []string{"overwrite", "whiteout", "opaque", "directory", "hardlink"} {
		t.Run(action, func(t *testing.T) {
			first, firstID := imageRPMLayer(t, db, rpmPath, nil)
			var entries []tarEntry
			switch action {
			case "overwrite":
				replacement, err := os.ReadFile(rpmTestSQLite(t, rpmTestHeader(3)))
				if err != nil {
					t.Fatal(err)
				}
				entries = []tarEntry{{name: rpmPath, data: replacement}}
			case "whiteout":
				entries = []tarEntry{{name: "var/lib/rpm/.wh.rpmdb.sqlite"}}
			case "opaque":
				entries = []tarEntry{{name: "var/lib/rpm/.wh..wh..opq"}}
			case "directory":
				entries = []tarEntry{{name: rpmPath, typeflag: tar.TypeDir}}
			case "hardlink":
				entries = []tarEntry{{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", typeflag: tar.TypeLink, link: rpmPath}, {name: "var/lib/rpm/.wh.rpmdb.sqlite"}}
			}
			next := buildTar(t, entries)
			r, err := Archive(imageRPMArchive(t, [][]byte{first, next}, []string{firstID, digestOf(next)}), Options{})
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "overwrite":
				assertImageRPM(t, r, 3, rpmPath)
			case "hardlink":
				assertImageRPM(t, r, 2, "usr/lib/sysimage/rpm/rpmdb.sqlite")
			default:
				if len(r.Packages) != 0 {
					t.Fatalf("removed RPM packages survived: %+v", r.Packages)
				}
			}
		})
	}
}

func TestImageRPMCleanupFailure(t *testing.T) {
	db := rpmTestSQLite(t, rpmTestHeader(2))
	blob, diffID := imageRPMLayer(t, db, "var/lib/rpm/rpmdb.sqlite", nil)
	for _, mode := range []string{"digest", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			expected := diffID
			if mode == "digest" {
				expected = "sha256:" + strings.Repeat("0", 64)
			}
			archive := imageRPMArchive(t, [][]byte{blob}, []string{expected})
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := Options{Progress: func(p Progress) {
				if mode == "cancel" && p.Stage == "catalog" {
					cancel()
				}
			}}
			_, err := archiveContext(ctx, archive, opts)
			if err == nil {
				t.Fatal("expected scan failure")
			}
			leftovers, err := filepath.Glob(filepath.Join(tmp, "*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("temporary files leaked: %v, %v", leftovers, err)
			}
		})
	}
}

func TestImageRPMLargeSymlink(t *testing.T) {
	smallRPMTestLimits(t)
	db := rpmTestSQLite(t, rpmTestHeader(2))
	if err := os.Truncate(db, maxFileMetadata+4096); err != nil {
		t.Fatal(err)
	}
	const rpmPath = "var/lib/rpm/rpmdb.sqlite"
	blob, diffID := imageRPMLayer(t, db, "payload/database", []tarEntry{{name: rpmPath, typeflag: tar.TypeSymlink, link: "/payload/database"}})
	r, err := Archive(imageRPMArchive(t, [][]byte{blob}, []string{diffID}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertImageRPM(t, r, 2, rpmPath)
}

func TestImageRPMMetadataAliases(t *testing.T) {
	db, err := os.ReadFile(rpmTestSQLite(t, rpmTestHeader(2)))
	if err != nil {
		t.Fatal(err)
	}
	const rpmPath = "var/lib/rpm/rpmdb.sqlite"
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			// An already retained metadata file can also be an RPM link target.
			target := "package-lock.json"
			raw := buildTar(t, []tarEntry{{name: target, data: db}, {name: rpmPath, typeflag: typ, link: "/" + target}, {name: "etc/os-release", data: []byte("ID=rocky\nVERSION_ID=9.4\n")}})
			r, err := Archive(imageRPMArchive(t, [][]byte{raw}, []string{digestOf(raw)}), Options{})
			if err != nil {
				t.Fatal(err)
			}
			assertImageRPM(t, r, 2, rpmPath)
			// Preserve ordinary metadata aliases even when their bytes came from a
			// path that is now retained on disk instead of in memory.
			raw = buildTar(t, []tarEntry{{name: rpmPath, data: []byte("ID=rocky\nVERSION_ID=9.4\n")}, {name: "etc/os-release", typeflag: typ, link: "/" + rpmPath}})
			r, err = Archive(imageRPMArchive(t, [][]byte{raw}, []string{digestOf(raw)}), Options{})
			if err != nil || r.OSName != "rocky" || r.OSVersion != "9.4" {
				t.Fatalf("metadata alias: OS=%+v err=%v", r.OS, err)
			}
		})
	}
}

func TestImageRPMReadLimits(t *testing.T) {
	db := rpmTestSQLite(t, rpmTestHeader(2))
	data, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"truncated", "budget", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := newUnpacker(ctx, Options{})
			defer u.Close()
			var rd io.Reader = bytes.NewReader(data)
			size := int64(len(data))
			switch mode {
			case "truncated":
				size++
			case "budget":
				rd = &decompressionReader{rd: rd, remaining: size - 1}
			case "cancel":
				rd = &imageRPMCancelReader{rd: rd, cancel: cancel}
			}
			_, err := u.readEntry("var/lib/rpm/rpmdb.sqlite", rd, &tar.Header{Size: size}, "layer")
			if err == nil {
				t.Fatal("expected bounded RPM copy failure")
			}
			if mode == "budget" && !strings.Contains(err.Error(), "decompression limit exceeded") {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(tmp, "*", "*"))
			if err != nil || len(files) != 0 {
				t.Fatalf("failed copy leaked files: %v, %v", files, err)
			}
			u.Close()
			entries, err := os.ReadDir(tmp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cleanup leaked directories: %v, %v", entries, err)
			}
		})
	}
}

type imageRPMCancelReader struct {
	rd     io.Reader
	cancel context.CancelFunc
}

func (r *imageRPMCancelReader) Read(p []byte) (int, error) {
	n, err := r.rd.Read(p)
	r.cancel()
	return n, err
}

func TestImageRPMRootfs(t *testing.T) {
	smallRPMTestLimits(t)
	db := rpmTestSQLite(t, rpmTestHeader(2))
	if err := os.Truncate(db, maxFileMetadata+4096); err != nil {
		t.Fatal(err)
	}
	blob, _ := imageRPMLayer(t, db, "var/lib/rpm/rpmdb.sqlite", nil)
	archive := writeTemp(t, "rootfs.tar.gz", blob)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	r, err := rootfsArchive(context.Background(), archive, Options{})
	if err != nil || len(r.Packages) != 1 {
		t.Fatalf("rootfs RPM: packages=%+v err=%v", r.Packages, err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files leaked: %v, %v", entries, err)
	}
}

func TestImageRPMDiscardedCopies(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	const rpmPath = "var/lib/rpm/rpmdb.sqlite"
	for _, epoch := range []uint32{2, 3} {
		data, err := os.ReadFile(rpmTestSQLite(t, rpmTestHeader(epoch)))
		if err != nil {
			t.Fatal(err)
		}
		if err := u.applyTar(bytes.NewReader(buildTar(t, []tarEntry{{name: rpmPath, data: data}})), fmt.Sprint(epoch)); err != nil {
			t.Fatal(err)
		}
		files, err := filepath.Glob(filepath.Join(tmp, "bongsu-image-rpm-*", "*"))
		if err != nil || len(files) != 1 {
			t.Fatalf("expected only the final RPM copy: %v, %v", files, err)
		}
	}
	if err := u.applyTar(bytes.NewReader(buildTar(t, []tarEntry{{name: "var/lib/rpm/.wh.rpmdb.sqlite"}})), "whiteout"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(tmp, "bongsu-image-rpm-*", "*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("whiteout retained a copy: %v, %v", files, err)
	}
}

func TestImageRPMParseErrors(t *testing.T) {
	db := rpmTestSQLite(t, rpmTestHeader(2), []byte("invalid header"))
	blob, diffID := imageRPMLayer(t, db, "var/lib/rpm/rpmdb.sqlite", nil)
	r, err := Archive(imageRPMArchive(t, [][]byte{blob}, []string{diffID}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertImageRPM(t, r, 2, "var/lib/rpm/rpmdb.sqlite")
	if r.Scan == nil || !r.Scan.Partial || r.Scan.SkippedErrors != 1 {
		t.Fatalf("RPM parse errors not counted: %+v", r.Scan)
	}
}
