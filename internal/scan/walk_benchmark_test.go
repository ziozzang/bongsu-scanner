package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// BenchmarkWalkSynthetic includes executable probing, 50,000 regular files,
// 2,000 directories, and 300 lockfiles. Tree creation is outside the timer.
func BenchmarkWalkSynthetic(b *testing.B) {
	root := b.TempDir()
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.2.3","license":"MIT"}}}`)
	for dir := range 2000 {
		p := filepath.Join(root, fmt.Sprintf("dir-%04d", dir))
		if err := os.Mkdir(p, 0755); err != nil {
			b.Fatal(err)
		}
		for file := range 25 {
			name, data, mode := fmt.Sprintf("file-%02d.txt", file), []byte("ordinary"), os.FileMode(0644)
			if file == 0 && dir < 300 {
				name, data = "package-lock.json", lock
			} else if file == 1 {
				data, mode = []byte("#!/bin/sh\nexit 0\n"), 0755
			}
			if err := os.WriteFile(filepath.Join(p, name), data, mode); err != nil {
				b.Fatal(err)
			}
		}
	}
	for _, workers := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				w := newWalkState(context.Background(), root, Options{}, false)
				w.workers = workers
				if err := walkTree(w.ctx, root, w.opts, w); err != nil {
					b.Fatal(err)
				}
				if w.meta.FilesVisited != 50000 || w.indexed != 300 || w.metadata().Partial {
					b.Fatalf("unexpected walk: indexed=%d metadata=%+v", w.indexed, w.meta)
				}
			}
		})
	}
}

func BenchmarkReadFileForWalk(b *testing.B) {
	data := make([]byte, 1<<20)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		if _, err := readFileForWalk(context.Background(), "package-lock.json", bytes.NewReader(data), int64(len(data)), maxMetadata); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHostScan is opt-in because it reads the real host. It separates
// scanner allocation/RSS from the CLI's subsequent SPDX/CycloneDX rendering.
func BenchmarkHostScan(b *testing.B) {
	if os.Getenv("BONGSU_BENCH_HOST") != "1" {
		b.Skip("set BONGSU_BENCH_HOST=1 to benchmark the real host")
	}
	b.ReportAllocs()
	for range b.N {
		r, err := Target(context.Background(), "host", Options{})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(len(r.Packages)), "packages/op")
		b.ReportMetric(float64(r.Scan.FilesVisited), "files/op")
		runtime.KeepAlive(r)
	}
}
