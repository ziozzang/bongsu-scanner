package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Preserve the measured reader as a differential oracle, including error
// precedence, size accounting and SHA-256, rather than just package counts.
func legacyReadFileForWalk(ctx context.Context, name string, r io.Reader, size, allowed int64) (File, error) {
	limit := min(size, allowed, int64(maxMetadata))
	h := sha256.New()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(walkContextReader{ctx, r}, limit+1), h))
	if err != nil {
		return File{}, err
	}
	if int64(len(data)) > limit {
		return File{}, errMetadataLimit
	}
	if ctx != nil && ctx.Err() != nil {
		return File{}, ctx.Err()
	}
	return File{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Data: data}, nil
}

func TestWalkReaderMatchesLegacy(t *testing.T) {
	for _, size := range []int64{-1, 0, 1, 8, 1024, 4096} {
		for _, allowed := range []int64{-1, 0, 1, 8, 2048, maxMetadata} {
			for _, length := range []int{0, 1, 8, 1024, 4096} {
				body := bytes.Repeat([]byte("x"), length)
				want, wantErr := legacyReadFileForWalk(context.Background(), "go.mod", bytes.NewReader(body), size, allowed)
				got, err := readFileForWalk(context.Background(), "go.mod", bytes.NewReader(body), size, allowed)
				if !reflect.DeepEqual(got, want) || err != wantErr {
					t.Fatalf("size=%d allowed=%d length=%d: got %+v/%v, want %+v/%v", size, allowed, length, got, err, want, wantErr)
				}
			}
		}
	}
	for _, fault := range []error{io.EOF, io.ErrUnexpectedEOF, os.ErrPermission} {
		for _, size := range []int64{0, 3, 8} {
			reader := func() io.Reader {
				return reviewReadFunc(func(p []byte) (int, error) { return copy(p, "data"), fault })
			}
			want, wantErr := legacyReadFileForWalk(context.Background(), "go.mod", reader(), size, 8)
			got, err := readFileForWalk(context.Background(), "go.mod", reader(), size, 8)
			if !reflect.DeepEqual(got, want) || err != wantErr {
				t.Fatalf("fault=%v size=%d: got %+v/%v, want %+v/%v", fault, size, got, err, want, wantErr)
			}
		}
	}
}

func TestWalkDescriptorMatchesConfinedPathWalk(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":        "ID=debian\nVERSION_ID=13\n",
		"var/lib/dpkg/status":   "Package: base\nVersion: 1\n\n",
		"skip/requirements.txt": "excluded==1\n",
		"plain":                 "contents", "script": "#!/bin/sh\nexit 0\n",
	}
	for i := range 10 {
		files[fmt.Sprintf("dir-%02d/nested/package-lock.json", i)] = fmt.Sprintf(`{"packages":{"node_modules/example":{"version":"1","license":"license-%d"}}}`, i)
	}
	writeTree(t, root, files)
	if err := os.Chmod(filepath.Join(root, "script"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir-00", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{
		{}, {IncludeFileHashes: true}, {SkipBinaries: true}, {OneFileSystem: true},
		{MaxFiles: 9}, {MaxTotalBytes: 150}, {Exclude: []string{"skip", "dir-0[24]"}},
	} {
		t.Run(fmt.Sprintf("%+v", opts), func(t *testing.T) {
			fast := newWalkState(context.Background(), root, opts, false)
			legacy := newWalkState(context.Background(), root, opts, false)
			// Exhausting the descriptor budget selects the original confined
			// full-path traversal and DirEntry.Info for the entire tree.
			legacy.openDirs = 64
			wantErr := walkTree(legacy.ctx, root, opts, legacy)
			err := walkTree(fast.ctx, root, opts, fast)
			got, gotOS := fast.catalog.finish()
			want, wantOS := legacy.catalog.finish()
			gotBins, _ := fast.binaries.finish()
			wantBins, _ := legacy.binaries.finish()
			if err != wantErr || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotOS, wantOS) ||
				!reflect.DeepEqual(gotBins, wantBins) || !reflect.DeepEqual(fast.fs, legacy.fs) ||
				!reflect.DeepEqual(fast.metadata(), legacy.metadata()) || fast.parsedBytes != legacy.parsedBytes || fast.indexed != legacy.indexed {
				t.Fatalf("descriptor and confined path results differ: errors %v/%v, metadata %+v/%+v, packages %+v/%+v", err, wantErr, fast.metadata(), legacy.metadata(), got, want)
			}
			if fast.openDirs != 0 || fast.currentDir != nil || legacy.openDirs != 64 {
				t.Fatal("directory descriptors not restored")
			}
		})
	}
}

func TestWalkDescriptorBudgetAndCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux descriptor traversal")
	}
	root := t.TempDir()
	rel := strings.Repeat("d/", 80) + "go.mod"
	writeTree(t, root, map[string]string{rel: "module app\nrequire example.com/a v1.0.0\n"})
	for _, cancelWalk := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		w := newWalkState(ctx, root, Options{SkipBinaries: true}, false)
		var handles []*os.File
		maxOpen, fallback := 0, false
		w.testHook = func(p string) {
			maxOpen = max(maxOpen, w.openDirs)
			if w.currentDir != nil {
				handles = append(handles, w.currentDir)
			} else if w.openDirs == 64 {
				fallback = true
			}
			if cancelWalk && p == filepath.Join(root, rel) {
				cancel()
			}
		}
		err := walkTree(ctx, root, w.opts, w)
		cancel()
		if cancelWalk && !errors.Is(err, context.Canceled) || !cancelWalk && err != nil {
			t.Fatal(err)
		}
		if maxOpen != 64 || !fallback || w.openDirs != 0 || w.currentDir != nil {
			t.Fatalf("descriptor budget or cleanup: peak=%d fallback=%t retained=%d", maxOpen, fallback, w.openDirs)
		}
		for _, f := range handles {
			if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("descriptor left open: %v", err)
			}
		}
	}
}

func TestWalkDescriptorAncestorReplacement(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeTree(t, root, map[string]string{"dir/go.mod": "module safe\nrequire example.com/safe v1.0.0\n"})
	writeTree(t, outside, map[string]string{"go.mod": "module unsafe\nrequire example.com/escaped v1.0.0\n"})
	w := newWalkState(context.Background(), root, Options{}, false)
	w.testHook = func(p string) {
		if p == filepath.Join(root, "dir/go.mod") {
			if err := os.Rename(filepath.Join(root, "dir"), filepath.Join(root, "saved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := walkTree(w.ctx, root, w.opts, w); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := w.catalog.finish()
	for _, p := range pkgs {
		if p.Name == "escaped" {
			t.Fatal("replacement ancestor escaped confinement")
		}
	}
}
