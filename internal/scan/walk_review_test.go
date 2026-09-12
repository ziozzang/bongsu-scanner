package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestReviewFileMountExclusions(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"var/lib/dpkg/status": "Package: foreign\nVersion: 1\n",
		"requirements.txt":    "foreign==1\n",
		"plain.txt":           "foreign contents",
	})
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "mountinfo")
	old := mountInfoPath
	mountInfoPath = fixture
	t.Cleanup(func() { mountInfoPath = old })
	for _, fstype := range []string{"ext4", "tmpfs"} {
		var table strings.Builder
		for i, rel := range []string{"var/lib/dpkg/status", "requirements.txt", "plain.txt"} {
			fmt.Fprintf(&table, "%d 1 8:1 /external/file %s rw - %s /dev/root rw\n", i+2, filepath.Join(realRoot, rel), fstype)
		}
		if err := os.WriteFile(fixture, []byte(table.String()), 0600); err != nil {
			t.Fatal(err)
		}
		for _, oneFS := range []bool{false, true} {
			for _, hashes := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/onefs=%t/hashes=%t", fstype, oneFS, hashes), func(t *testing.T) {
					r, err := DirectoryContext(context.Background(), root, "test", Options{OneFileSystem: oneFS, IncludeFileHashes: hashes, SkipBinaries: true})
					if err != nil {
						t.Fatal(err)
					}
					if oneFS || fstype == "tmpfs" {
						if len(r.Packages) != 0 || len(r.Files) != 0 || r.Scan.ExcludedCount != 3 || r.Scan.Partial {
							t.Fatalf("file mounts leaked or miscounted: packages=%+v files=%+v scan=%+v", r.Packages, r.Files, r.Scan)
						}
					} else if len(r.Packages) != 2 || r.Scan.ExcludedCount != 0 {
						t.Fatalf("ordinary mount excluded without onefs: packages=%+v scan=%+v", r.Packages, r.Scan)
					}
				})
			}
		}
	}
}

type reviewDeviceInfo struct{ fs.FileInfo }

func (i reviewDeviceInfo) Sys() any {
	st := *i.FileInfo.Sys().(*syscall.Stat_t)
	st.Dev++
	return &st
}

func TestReviewOneFileSystemChecksOpenedFile(t *testing.T) {
	for _, prepass := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepass=%t", prepass), func(t *testing.T) {
			root := t.TempDir()
			rel := "var/lib/dpkg/status"
			writeTree(t, root, map[string]string{rel: "Package: foreign\nVersion: 1\n"})
			p := filepath.Join(root, rel)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if deviceOf(info) == 0 {
				t.Skip("file device unavailable")
			}
			w := newWalkState(context.Background(), root, Options{OneFileSystem: true, IncludeFileHashes: true, SkipBinaries: true}, false)
			w.rootDev = deviceOf(info) + 1
			if prepass {
				w.safeRoot, err = os.OpenRoot(root)
				if err != nil {
					t.Fatal(err)
				}
				defer w.safeRoot.Close()
				w.preloaded = make(map[string]bool)
				err = w.preloadInventory(rel)
			} else {
				// The cached entry appears to be on the root device; only fstat
				// on the opened file can detect the simulated replacement.
				err = w.visitFile(p, reviewCachedEntry{reviewDeviceInfo{info}})
			}
			if err != nil {
				t.Fatal(err)
			}
			pkgs, _ := w.catalog.finish()
			if len(pkgs) != 0 || len(w.fs) != 0 || w.meta.ExcludedCount != 1 || w.meta.Excluded[0] != "onefs "+p || w.metadata().Partial {
				t.Fatalf("opened file device ignored: packages=%+v files=%v meta=%+v", pkgs, keys(w.fs), w.meta)
			}
			if prepass {
				if err := w.visitFile(p, reviewCachedEntry{info}); err != nil {
					t.Fatal(err)
				}
				if w.meta.ExcludedCount != 1 {
					t.Fatalf("prepass exclusion counted twice: %+v", w.meta)
				}
			}
		})
	}
}

func TestReviewRealFileBindMount(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux mount namespaces")
	}
	const childEnv = "BONGSU_REVIEW_FILE_BIND_CHILD"
	if os.Getenv(childEnv) != "1" {
		if out, err := exec.Command("unshare", "-rm", "true").CombinedOutput(); err != nil {
			t.Skipf("mount namespace unavailable: %v: %s", err, out)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-rm", exe, "-test.run=^TestReviewRealFileBindMount$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		t.Logf("namespace test: %s", out)
		if err != nil {
			t.Fatalf("namespace test failed: %v", err)
		}
		return
	}
	root, outside := t.TempDir(), t.TempDir()
	files := map[string]string{
		"var/lib/dpkg/status": "Package: foreign\nVersion: 1\n",
		"requirements.txt":    "foreign==1\n",
	}
	writeTree(t, outside, files)
	writeTree(t, root, files)
	for rel := range files {
		dst := filepath.Join(root, rel)
		if out, err := exec.Command("mount", "--bind", filepath.Join(outside, rel), dst).CombinedOutput(); err != nil {
			t.Skipf("file bind mount unavailable: %v: %s", err, out)
		}
		t.Cleanup(func() {
			if out, err := exec.Command("umount", dst).CombinedOutput(); err != nil {
				t.Errorf("unmount failed: %v: %s", err, out)
			}
		})
	}
	r, err := DirectoryContext(context.Background(), root, "test", Options{OneFileSystem: true, IncludeFileHashes: true, SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 0 || len(r.Files) != 0 || r.Scan.ExcludedCount != 2 || r.Scan.Partial {
		t.Fatalf("bind-mounted files leaked: packages=%+v files=%+v scan=%+v", r.Packages, r.Files, r.Scan)
	}
}

func TestReviewCriticalInventorySurvivesBudget(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/package-lock.json":         strings.Repeat(" ", 128),
		"usr/lib/os-release":          "ID=debian\nVERSION_ID=13\n",
		"var/lib/dpkg/status":         "Package: libc6\nStatus: install ok installed\nVersion: 2.41\n\n",
		"var/lib/dpkg/status.d/extra": "Package: extra\nVersion: 1\n\n",
	})
	r, err := Target(context.Background(), "host", Options{HostRoot: root, MaxTotalBytes: 16, SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.OSName != "debian" || packageNames(r)["libc6"].Type != "deb" || packageNames(r)["extra"].Type != "deb" {
		t.Fatalf("critical inventory lost: OS=%s packages=%v", r.OSName, r.Packages)
	}
	if !r.Scan.Partial || r.Scan.SkippedErrors != 0 || r.Scan.MetadataSkipped != 1 {
		t.Fatalf("metadata: %+v", r.Scan)
	}
}

func TestReviewDirectorySwapDoesNotEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeTree(t, root, map[string]string{"dir/go.mod": "module safe\n"})
	writeTree(t, outside, map[string]string{"go.mod": "module escaped\n"})
	w := newWalkState(context.Background(), root, Options{SkipBinaries: true}, false)
	w.testHook = func(p string) {
		if p == filepath.Join(root, "dir") {
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := walkTree(w.ctx, root, w.opts, w); err != nil {
		t.Fatal(err)
	}
	if len(w.fs) != 0 || !w.metadata().Partial {
		t.Fatalf("symlink followed: files=%v metadata=%+v", keys(w.fs), w.metadata())
	}
}

// A cached DirEntry reproduces a file changing after its original stat.
type reviewCachedEntry struct{ fs.FileInfo }

func (d reviewCachedEntry) Type() fs.FileMode          { return d.Mode().Type() }
func (d reviewCachedEntry) Info() (fs.FileInfo, error) { return d.FileInfo, nil }

func TestReviewGrowingMetadataDropped(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "go.mod")
	writeTree(t, root, map[string]string{"go.mod": "module old\n"})
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 256)), 0600); err != nil {
		t.Fatal(err)
	}
	w := newWalkState(context.Background(), root, Options{MaxTotalBytes: 32, SkipBinaries: true}, false)
	if err := w.visitFile(p, reviewCachedEntry{st}); err != nil {
		t.Fatal(err)
	}
	if len(w.fs) != 0 || !w.metadata().Partial || w.meta.MetadataSkipped != 1 || w.meta.SkippedErrors != 0 {
		t.Fatalf("growing file accepted: bytes=%d metadata=%+v", w.totalBytes, w.metadata())
	}
}

func TestReviewOversizedMetadataSkippedWithoutHashes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "package-lock.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxMetadata + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r, err := DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 0 || !r.Scan.Partial || r.Scan.MetadataSkipped != 1 {
		t.Fatalf("oversized metadata retained: files=%d scan=%+v", len(r.Files), r.Scan)
	}
	r, err = DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true, IncludeFileHashes: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 1 || len(r.Files[0].Data) != 0 || r.Files[0].SHA256 == "" || r.Scan.MetadataSkipped != 1 || !r.Scan.Partial {
		t.Fatalf("oversized hash-only file: %+v scan=%+v", r.Files, r.Scan)
	}
}

func TestReviewCancellationAtLastFile(t *testing.T) {
	for _, stage := range []string{"entry", "file", "catalog"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, map[string]string{"go.mod": "module last\n"})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := Options{SkipBinaries: true, Verbose: true, Progress: func(p Progress) {
				if p.Stage == stage {
					cancel()
				}
			}}
			var err error
			if stage == "entry" {
				w := newWalkState(ctx, root, opts, false)
				w.testHook = func(string) { cancel() }
				err = walkTree(ctx, root, opts, w)
				if len(w.fs) != 0 {
					t.Error("read file after cancellation")
				}
			} else {
				_, err = DirectoryContext(ctx, root, "test", opts)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation ignored: %v", err)
			}
		})
	}
}

func TestReviewHostDirectoryReleasesMetadata(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"go.mod": "module app\nrequire example.com/a v1.0.0\n", "plain.txt": "unused"})
	r, err := DirectoryContext(context.Background(), root, "host", Options{hostPolicy: true, SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 1 || r.Files != nil {
		t.Fatalf("host retains file data: packages=%d files=%d", len(r.Packages), len(r.Files))
	}
}

func TestReviewCriticalInventoryNotReadTwice(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release": "ID=first\n", "var/lib/dpkg/status": "Package: first\nVersion: 1\n\n",
		"lib/apk/db/installed": "P:apk-first\nV:1\n\n", "usr/lib/apk/db/installed": "P:apk-second\nV:2\n\n",
	})
	w := newWalkState(context.Background(), root, Options{MaxTotalBytes: 1, SkipBinaries: true}, false)
	w.testHook = func(p string) {
		if interesting(w.rel(p)) {
			if err := os.WriteFile(p, []byte("replaced"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := walkTree(w.ctx, root, w.opts, w); err != nil {
		t.Fatal(err)
	}
	if len(w.fs) != 0 || w.totalBytes != 0 || w.meta.FilesVisited != 4 || w.metadata().Partial {
		t.Fatalf("inventory accounting: bytes=%d metadata=%+v files=%v", w.totalBytes, w.metadata(), keys(w.fs))
	}
	pkgs, osr := w.catalog.finish()
	if osr == nil || osr.ID != "first" || len(pkgs) != 3 {
		t.Fatalf("inventory re-read: os=%+v packages=%+v", osr, pkgs)
	}
}

func TestReviewCriticalInventorySymlinkSafety(t *testing.T) {
	for _, link := range []string{"var", "var/lib", "var/lib/dpkg", "var/lib/dpkg/status", "var/lib/dpkg/status.d", "etc/os-release"} {
		t.Run(link, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			writeTree(t, outside, map[string]string{"lib/dpkg/status": "Package: escaped\nVersion: 1\n", "status": "Package: escaped\nVersion: 1\n", "os-release": "ID=escaped\n", "pkg": "Package: escaped\nVersion: 1\n"})
			dst := outside
			switch link {
			case "var/lib":
				dst = filepath.Join(outside, "lib")
			case "var/lib/dpkg":
				dst = filepath.Join(outside, "lib/dpkg")
			case "var/lib/dpkg/status":
				dst = filepath.Join(outside, "status")
			case "etc/os-release":
				dst = filepath.Join(outside, "os-release")
			}
			p := filepath.Join(root, link)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dst, p); err != nil {
				t.Fatal(err)
			}
			r, err := DirectoryContext(context.Background(), root, "test", Options{SkipBinaries: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Packages) != 0 || r.OS != nil {
				t.Fatalf("outside inventory leaked: %+v", r)
			}
		})
	}
}

type reviewReadFunc func([]byte) (int, error)

func (f reviewReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestReviewBoundedAndCancelledReads(t *testing.T) {
	for _, tc := range []struct{ size, allowed, want int64 }{{8, 100, 9}, {100, 8, 9}, {maxMetadata + 10, maxMetadata + 10, maxMetadata + 1}} {
		var read int64
		infinite := reviewReadFunc(func(p []byte) (int, error) { read += int64(len(p)); return len(p), nil })
		_, err := readFileForWalk(context.Background(), "go.mod", infinite, tc.size, tc.allowed)
		if !errors.Is(err, errMetadataLimit) || read != tc.want {
			t.Fatalf("read=%d want=%d err=%v", read, tc.want, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	r := reviewReadFunc(func(p []byte) (int, error) { reads++; cancel(); p[0] = 'x'; return 1, nil })
	_, err := readFileForWalk(ctx, "go.mod", r, 8, 8)
	if !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatalf("reads=%d err=%v", reads, err)
	}
	_, err = io.ReadAll(walkContextReader{ctx, reviewReadFunc(func([]byte) (int, error) { t.Fatal("read after cancel"); return 0, io.EOF })})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReviewUnparsedFileDataNotRetained(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"plain.txt": "unused", "var/lib/rpm/rpmdb.sqlite": "not parsed"})
	r, err := DirectoryContext(context.Background(), root, "test", Options{IncludeFileHashes: true, SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 2 {
		t.Fatalf("files=%d", len(r.Files))
	}
	for _, f := range r.Files {
		if f.Data != nil || f.SHA256 == "" {
			t.Fatalf("unparsed data retained: %+v", f)
		}
	}
}

func TestReviewOneFileSystemChecksOpenedDirectory(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"go.mod": "module other-device\n"})
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	w := newWalkState(context.Background(), root, Options{OneFileSystem: true, SkipBinaries: true}, false)
	// Simulate a replacement directory on another device after enterDir's
	// cached entry check; walkDir must check the opened handle independently.
	w.rootDev = deviceOf(info) + 1
	if err := w.walkDir(root); err != nil {
		t.Fatal(err)
	}
	if len(w.fs) != 0 || w.meta.ExcludedCount != 1 || !strings.HasPrefix(w.meta.Excluded[0], "onefs ") {
		t.Fatalf("opened device ignored: files=%v meta=%+v", keys(w.fs), w.meta)
	}
}

type reviewReadAtFunc func([]byte, int64) (int, error)

func (f reviewReadAtFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

func TestReviewBinaryReadsHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	r := walkContextReaderAt{ctx, reviewReadAtFunc(func(p []byte, _ int64) (int, error) {
		reads++
		cancel()
		return len(p), nil
	})}
	for range 2 {
		if _, err := r.ReadAt(make([]byte, 4), 0); !errors.Is(err, context.Canceled) {
			t.Fatalf("binary read ignored cancellation: %v", err)
		}
	}
	if reads != 1 {
		t.Fatalf("read after cancellation: %d reads", reads)
	}
}

func TestReviewHostMetadataCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Target(ctx, "host", Options{HostRoot: t.TempDir(), NoHostMetadata: true, Progress: func(p Progress) {
		if p.Stage == "metadata" {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("host returned after cancellation: %v", err)
	}
}

func TestReviewStreamingMetadataBudget(t *testing.T) {
	root := t.TempDir()
	body := `{"packages":{"node_modules/first":{"version":"1.0.0"}}}`
	body += strings.Repeat(" ", (1<<20)-len(body))
	writeTree(t, root, map[string]string{
		"a/package-lock.json": body, "b/package-lock.json": body, "c/package-lock.json": body,
	})
	r, err := DirectoryContext(context.Background(), root, "test", Options{MaxTotalBytes: 1536 << 10, SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 1 || r.Packages[0].Source != "a/package-lock.json" || r.Scan.MetadataSkipped != 2 || !r.Scan.Partial || r.Scan.LimitReached != "max-total-bytes" {
		t.Fatalf("parsed byte budget: packages=%+v scan=%+v", r.Packages, r.Scan)
	}
	if len(r.Files) != 0 {
		t.Fatalf("metadata retained without file hashes: %d files", len(r.Files))
	}
}

func TestReviewStreamingReleasesEachFile(t *testing.T) {
	for _, hashes := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata-only", true: "hashes"}[hashes], func(t *testing.T) {
			root := t.TempDir()
			body := `{"packages":{"node_modules/first":{"version":"1.0.0"}}}`
			body += strings.Repeat(" ", (1<<20)-len(body))
			w := newWalkState(context.Background(), root, Options{IncludeFileHashes: hashes, SkipBinaries: true}, false)
			for _, dir := range []string{"a", "b", "c"} {
				rel := dir + "/package-lock.json"
				writeTree(t, root, map[string]string{rel: body})
				p := filepath.Join(root, rel)
				st, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := w.visitFile(p, reviewCachedEntry{st}); err != nil {
					t.Fatal(err)
				}
				if w.totalBytes > int64(len(body)) {
					t.Errorf("retained %d bytes after %s; largest file=%d", w.totalBytes, rel, len(body))
				}
				if !hashes && len(w.fs) != 0 {
					t.Errorf("retained %d file records without hashes", len(w.fs))
				}
				for _, f := range w.fs {
					if f.Data != nil || f.SHA256 == "" || f.Size != int64(len(body)) {
						t.Errorf("file %s: retained data=%d hash=%q size=%d", f.Path, len(f.Data), f.SHA256, f.Size)
					}
				}
			}
			pkgs, _ := w.catalog.finish()
			if w.totalBytes != 0 || w.parsedBytes != 3<<20 || len(pkgs) != 1 || pkgs[0].Source != "a/package-lock.json;b/package-lock.json;c/package-lock.json" {
				t.Fatalf("stream accounting: retained=%d parsed=%d packages=%+v", w.totalBytes, w.parsedBytes, pkgs)
			}
			if hashes && len(w.fs) != 3 {
				t.Fatalf("file hashes missing: %d", len(w.fs))
			}
		})
	}
}

func TestReviewStreamingDefaultBudget(t *testing.T) {
	w := newWalkState(context.Background(), t.TempDir(), Options{}, false)
	if w.maxBytes != 4<<30 {
		t.Fatalf("default parsed byte budget=%d, want 4 GiB", w.maxBytes)
	}
}
