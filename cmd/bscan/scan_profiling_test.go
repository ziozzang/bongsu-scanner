package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanProfilingFiles(t *testing.T) {
	root, output := t.TempDir(), t.TempDir()
	cpu, heap := filepath.Join(output, "cpu.pprof"), filepath.Join(output, "heap.pprof")
	if err := cmdScan(context.Background(), []string{"--no-sign", "--cpuprofile", cpu, "--memprofile", heap, "--output", output, root}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cpu, heap} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(r)
		r.Close()
		if err != nil || len(decoded) == 0 {
			t.Fatalf("invalid profile %s: length=%d error=%v", p, len(decoded), err)
		}
	}
}

func TestScanProfilingCreationErrors(t *testing.T) {
	for _, name := range []string{"--cpuprofile", "--memprofile"} {
		if err := cmdScan(context.Background(), []string{name, t.TempDir(), "host"}); err == nil {
			t.Fatalf("%s ignored profile creation failure", name)
		}
	}
}

func TestScanProfilingFlagsHidden(t *testing.T) {
	old := os.Stderr
	capture, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = capture
	defer func() { os.Stderr = old; capture.Close() }()
	if err := cmdScan(context.Background(), []string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
	if _, err := capture.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(capture)
	if err != nil {
		t.Fatal(err)
	}
	help := string(data)
	if strings.Contains(help, "cpuprofile") || strings.Contains(help, "memprofile") || !strings.Contains(help, "skip-binaries") {
		t.Fatalf("unexpected scan help: %s", help)
	}
}
