package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func compareWalkStates(t *testing.T, got, want *walkState) {
	t.Helper()
	gp, goos := got.catalog.finish()
	wp, woos := want.catalog.finish()
	gb, _ := got.binaries.finish()
	wb, _ := want.binaries.finish()
	if !reflect.DeepEqual(gp, wp) || !reflect.DeepEqual(goos, woos) || !reflect.DeepEqual(gb, wb) ||
		!reflect.DeepEqual(got.fs, want.fs) || !reflect.DeepEqual(got.metadata(), want.metadata()) ||
		got.indexed != want.indexed || got.parsedBytes != want.parsedBytes {
		t.Fatalf("parallel result differs: metadata %+v / %+v; indexed %d / %d; parsed bytes %d / %d; catalog equal=%t binaries equal=%t hashes equal=%t",
			got.metadata(), want.metadata(), got.indexed, want.indexed, got.parsedBytes, want.parsedBytes,
			reflect.DeepEqual(gp, wp), reflect.DeepEqual(gb, wb), reflect.DeepEqual(got.fs, want.fs))
	}
	if got.openDirs != 0 || got.currentDir != nil || got.safeRoot != nil {
		t.Fatal("walk retained directory handles")
	}
}

// Run under -race: 50,000 files exercise concurrent probing, parsing,
// exclusion accounting and a deliberately unsynchronized progress callback.
func TestWalkParallel50000Equality(t *testing.T) {
	root := t.TempDir()
	for dir := range 500 {
		p := filepath.Join(root, fmt.Sprintf("dir-%03d", dir))
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
		for file := range 100 {
			name, data, mode := fmt.Sprintf("file-%03d", file), "ordinary", os.FileMode(0644)
			if file == 0 {
				name = "package-lock.json"
				data = fmt.Sprintf(`{"packages":{"node_modules/example":{"version":"1","license":"license-%03d"}}}`, dir)
			} else if file == 1 {
				data, mode = "#!/bin/sh\nexit 0\n", 0755
			}
			if err := os.WriteFile(filepath.Join(p, name), []byte(data), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink("dir-000", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	progress := 0
	opts := Options{IncludeFileHashes: true, Exclude: []string{"file-099"}, Verbose: true,
		Progress: func(Progress) { progress++ },
	}
	want := newWalkState(context.Background(), root, opts, false)
	want.workers = 1
	if err := walkTree(want.ctx, root, opts, want); err != nil {
		t.Fatal(err)
	}
	if want.meta.FilesVisited != 50000 || want.meta.ExcludedCount != 500 {
		t.Fatal(want.metadata())
	}
	for _, workers := range []int{4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			got := newWalkState(context.Background(), root, opts, false)
			got.workers = workers
			if err := walkTree(got.ctx, root, opts, got); err != nil {
				t.Fatal(err)
			}
			compareWalkStates(t, got, want)
		})
	}
	if progress == 0 {
		t.Fatal("missing progress")
	}
}

func TestWalkParallelOrderingAndLimits(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":        "ID=debian\nVERSION_ID=13\n",
		"var/lib/dpkg/status":   "Package: critical\nVersion: 1\n\n",
		"a/z/package-lock.json": `{"packages":{"node_modules/example":{"version":"1","license":"first"}}}`,
		"a-/package-lock.json":  `{"packages":{"node_modules/example":{"version":"1","license":"second"}}}`,
	}
	for i := range 40 {
		files[fmt.Sprintf("m%02d/requirements.txt", i)] = "duplicate==1\n"
	}
	writeTree(t, root, files)
	for _, opts := range []Options{{}, {MaxFiles: 1}, {MaxFiles: 9}, {MaxTotalBytes: 1}, {MaxTotalBytes: 220}, {OneFileSystem: true}, {SkipBinaries: true}} {
		t.Run(fmt.Sprintf("%+v", opts), func(t *testing.T) {
			want := newWalkState(context.Background(), root, opts, false)
			want.workers = 1
			wantErr := walkTree(want.ctx, root, opts, want)
			for _, workers := range []int{4, 8} {
				got := newWalkState(context.Background(), root, opts, false)
				got.workers = workers
				err := walkTree(got.ctx, root, opts, got)
				if !errors.Is(err, wantErr) {
					t.Fatalf("errors %v / %v", err, wantErr)
				}
				compareWalkStates(t, got, want)
			}
		})
	}
}

func TestWalkParallelCancellationDrains(t *testing.T) {
	root := t.TempDir()
	for i := range 100 {
		writeTree(t, root, map[string]string{fmt.Sprintf("d%03d/requirements.txt", i): "example==1\n"})
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		opts := Options{Verbose: true, Progress: func(p Progress) {
			if p.Stage == "file" {
				cancel()
			}
		}}
		w := newWalkState(ctx, root, opts, false)
		w.workers = 8
		err := walkTree(ctx, root, opts, w)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation: %v", err)
		}
		if w.currentDir != nil || w.openDirs != 0 || w.safeRoot != nil {
			t.Fatal("descriptors retained")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatalf("FD leak: %d -> %d", len(before), len(after))
	}
}

func TestWalkParallelDeepTree(t *testing.T) {
	root := t.TempDir()
	for i := range 12 {
		writeTree(t, root, map[string]string{fmt.Sprintf("branch%02d/", i) + strings.Repeat("d/", 80) + "go.mod": "module app\nrequire example.com/a v1.0.0\n"})
	}
	want := newWalkState(context.Background(), root, Options{}, false)
	want.workers = 1
	if err := walkTree(want.ctx, root, want.opts, want); err != nil {
		t.Fatal(err)
	}
	got := newWalkState(context.Background(), root, Options{}, false)
	got.workers = 8
	if err := walkTree(got.ctx, root, got.opts, got); err != nil {
		t.Fatal(err)
	}
	compareWalkStates(t, got, want)
}

func TestWalkParallelBinaryEqualityAndCap(t *testing.T) {
	root := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !isELF(data) || int64(len(data)) > maxGoBinary {
		t.Skip("test executable not a probeable ELF")
	}
	for i := range 12 {
		p := filepath.Join(root, fmt.Sprintf("d%02d", i))
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "binary"), data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	oversize := filepath.Join(root, "oversize")
	if err := os.WriteFile(oversize, data[:4], 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversize, maxGoBinary+1); err != nil {
		t.Fatal(err)
	}
	want := newWalkState(context.Background(), root, Options{}, false)
	want.workers = 1
	if err := walkTree(want.ctx, root, want.opts, want); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := want.binaries.finish()
	if len(pkgs) == 0 {
		t.Fatal("Go binary probe was not exercised")
	}
	got := newWalkState(context.Background(), root, Options{}, false)
	got.workers = 8
	if err := walkTree(got.ctx, root, got.opts, got); err != nil {
		t.Fatal(err)
	}
	compareWalkStates(t, got, want)
}

func TestWalkParallelSpoolPreservesBytesAndReportsFailure(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"d/requirements.txt": "invalid\xff==1\n"})
	want := newWalkState(context.Background(), root, Options{}, false)
	want.workers = 1
	if err := walkTree(want.ctx, root, want.opts, want); err != nil {
		t.Fatal(err)
	}
	got := newWalkState(context.Background(), root, Options{}, false)
	got.workers = 8
	if err := walkTree(got.ctx, root, got.opts, got); err != nil {
		t.Fatal(err)
	}
	compareWalkStates(t, got, want)

	t.Setenv("TMPDIR", filepath.Join(root, "missing"))
	broken := newWalkState(context.Background(), root, Options{}, false)
	broken.workers = 8
	if err := walkTree(broken.ctx, root, broken.opts, broken); err == nil || !strings.Contains(err.Error(), "walk result spool") {
		t.Fatalf("spool failure was not propagated: %v", err)
	}
	if broken.spool != nil || broken.safeRoot != nil || broken.currentDir != nil {
		t.Fatal("failed spool leaked handles")
	}
}
